## Overview

---

Uses the Have I Been Pwned? service to check whether email addresses, domains, or usernames were compromised in previous breaches. Uses [API v3](https://haveibeenpwned.com/api/v3).

## Configure Have I Been Pwned? V2 on Cortex XSOAR

---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Have I Been Pwned? V2.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __API Key__
    * __Maximum time per request (in seconds)__
    * __Email Severity: The DBot reputation for compromised emails (SUSPICIOUS or MALICIOUS)__
    * __Domain Severity: The DBot reputation for compromised domains (SUSPICIOUS or MALICIOUS)__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Fetched Incidents Data

---

## Commands

---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. pwned-email
2. pwned-domain
3. email
4. domain
5. pwned-username

### 1. pwned-email

---
Checks if an email address was compromised.

##### Base Command

`pwned-email`

##### Input

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| email | Comma-separated list of email addresses to check. | Required |

##### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Account.Email.Pwned-V2.Compromised.Vendor | String | For compromised email addresses, the vendor that made the decision. |
| Account.Email.Pwned-V2.Compromised.Reporters | String | For compromised email addresses, the reporters for the vendor to make the compromised decision. |
| Account.Email.Address | String | The email address. |
| Email.Malicious.Vendor | String | For malicious email addresses, the vendor that made the decision. |
| Email.Malicious.Description | String | For malicious email addresses, the reason that the vendor made the decision. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | Vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

##### Command Example

```!pwned-email email="michaljordan@gmail.com"```

##### Context Example

```
{
    "DBotScore": {
        "Vendor": "Have I Been Pwned? V2", 
        "Indicator": "michaljordan@gmail.com", 
        "Score": 2, 
        "Type": "email"
    }, 
    "Account.Email": {
        "Pwned-V2": {
            "Compromised": {
                "Vendor": "Have I Been Pwned? V2", 
                "Reporters": "Canva, Dubsmash, Modern Business Solutions, Straffic, TestGame"
            }
        }, 
        "Address": "michaljordan@gmail.com"
    }
}
```

##### Human Readable Output

### Have I Been Pwned query for email: *michaljordan@gmail.com*

#### Canva (canva.com): 137272116 records breached [Verified breach]

Date: __2019-05-24__

In May 2019, the graphic design tool website [Canva suffered a data breach](https://support.canva.com/contact/customer-support/may-24-security-incident-faqs/) that impacted 137 million subscribers. The exposed data included email addresses, usernames, names, cities of residence and passwords stored as bcrypt hashes for users not using social logins. The data was provided to HIBP by a source who requested it be attributed to "JimScott.Sec@protonmail.com".
Data breached: __Email addresses,Geographic locations,Names,Passwords,Usernames__

#### Dubsmash (dubsmash.com): 161749950 records breached [Verified breach]

Date: __2018-12-01__

In December 2018, the video messaging service [Dubsmash suffered a data breach](https://www.theregister.co.uk/2019/02/11/620_million_hacked_accounts_dark_web/). The incident exposed 162 million unique email addresses alongside usernames and PBKDF2 password hashes. In 2019, the data appeared listed for sale on a dark web marketplace (along with several other large breaches) and subsequently began circulating more broadly. The data was provided to HIBP by a source who requested it to be attributed to &quot;BenjaminBlue@exploit.im&quot;.
Data breached: __Email addresses,Geographic locations,Names,Passwords,Phone numbers,Spoken languages,Usernames__

#### Modern Business Solutions (modbsolutions.com): 58843488 records breached [Verified breach]

Date: __2016-10-08__

In October 2016, a large Mongo DB file containing tens of millions of accounts [was shared publicly on Twitter](https://twitter.com/0x2Taylor/status/784544208879292417) (the file has since been removed). The database contained over 58M unique email addresses along with IP addresses, names, home addresses, genders, job titles, dates of birth and phone numbers. The data was subsequently [attributed to &quot;Modern Business Solutions&quot;](http://news.softpedia.com/news/hacker-steals-58-million-user-records-from-data-storage-provider-509190.shtml), a company that provides data storage and database hosting solutions. They've yet to acknowledge the incident or explain how they came to be in possession of the data.
Data breached: __Dates of birth,Email addresses,Genders,IP addresses,Job titles,Names,Phone numbers,Physical addresses__

#### Straffic (straffic.io): 48580249 records breached [Verified breach]

Date: __2020-02-14__

In February 2020, Israeli marketing company [Straffic exposed a database with 140GB of personal data](https://www.databreachtoday.com/israeli-marketing-company-exposes-contacts-database-a-13785). The publicly accessible Elasticsearch database contained over 300M rows with 49M unique email addresses. Exposed data also included names, phone numbers, physical addresses and genders. In [their breach disclosure message](https://straffic.io/updates.php), Straffic stated that &quot;it is impossible to create a totally immune system, and these things can occur&quot;.
Data breached: __Email addresses,Genders,Names,Phone numbers,Physical addresses__

#### TestGame (zynga.com): 172869660 records breached [Verified breach]

Date: __2019-09-01__

In September 2019, game developer [TestGame (the creator of Words with Friends) suffered a data breach](https://www.cnet.com/news/words-with-friends-hack-reportedly-exposes-data-of-more-than-200m-players/). The incident exposed 173M unique email addresses alongside usernames and passwords stored as salted SHA-1 hashes. The data was provided to HIBP by [dehashed.com](https://dehashed.com/).
Data breached: __Email addresses,Passwords,Phone numbers,Usernames__

### 2. pwned-domain

---
Checks if a domain was compromised.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

##### Base Command

`pwned-domain`

##### Input

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| domain | Comma-separated list of domains to check. | Required |

##### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Domain.Pwned-V2.Compromised.Vendor | String | For compromised domains, the vendor that made the decision. |
| Domain.Pwned-V2.Compromised.Reporters | String | For compromised domains, the reporters for the vendor to make the compromised decision. |
| Domain.Name | String | Domain name. |
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. |
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | Vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

##### Command Example

```!pwned-domain domain="adobe.com"```

##### Context Example

```
{
    "Domain": {
        "Pwned-V2": {
            "Compromised": {
                "Vendor": "Have I Been Pwned? V2", 
                "Reporters": "Adobe"
            }
        }, 
        "Name": "adobe.com"
    }, 
    "DBotScore": {
        "Vendor": "Have I Been Pwned? V2", 
        "Indicator": "adobe.com", 
        "Score": 2, 
        "Type": "domain"
    }
}
```

##### Human Readable Output

### Have I Been Pwned query for domain: *adobe.com*

#### Adobe (adobe.com): 152445165 records breached [Verified breach]

Date: __2013-10-04__

In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and [many were quickly resolved back to plain text](http://stricture-group.com/files/adobe-top100.txt). The unencrypted hints also [disclosed much about the passwords](http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html) adding further to the risk that hundreds of millions of Adobe customers already faced.
Data breached: __Email addresses,Password hints,Passwords,Usernames__

### 3. email

---
Checks if an email address was compromised.

##### Base Command

`email`

##### Input

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| email | Comma-separated list of email addresses to check. | Required |

##### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Account.Email.Pwned-V2.Compromised.Vendor | String | For compromised email addresses, the vendor that made the decision. |
| Account.Email.Pwned-V2.Compromised.Reporters | String | For compromised email addresses, the reporters for the vendor to make the compromised decision. |
| Account.Email.Address | String | The email address. |
| Email.Malicious.Vendor | String | For malicious email addresses, the vendor that made the decision. |
| Email.Malicious.Description | String | For malicious email addresses, the reason that the vendor made the decision. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

##### Command Example

```!email email="michaljordan@gmail.com"```

##### Context Example

```
{
    "DBotScore": {
        "Vendor": "Have I Been Pwned? V2", 
        "Indicator": "michaljordan@gmail.com", 
        "Score": 2, 
        "Type": "email"
    }, 
    "Account.Email": {
        "Pwned-V2": {
            "Compromised": {
                "Vendor": "Have I Been Pwned? V2", 
                "Reporters": "Canva, Dubsmash, Modern Business Solutions, Straffic, TestGame"
            }
        }, 
        "Address": "michaljordan@gmail.com"
    }
}
```

##### Human Readable Output

### Have I Been Pwned query for email: *michaljordan@gmail.com*

#### Canva (canva.com): 137272116 records breached [Verified breach]

Date: __2019-05-24__

In May 2019, the graphic design tool website [Canva suffered a data breach](https://support.canva.com/contact/customer-support/may-24-security-incident-faqs/) that impacted 137 million subscribers. The exposed data included email addresses, usernames, names, cities of residence and passwords stored as bcrypt hashes for users not using social logins. The data was provided to HIBP by a source who requested it be attributed to "JimScott.Sec@protonmail.com".
Data breached: __Email addresses,Geographic locations,Names,Passwords,Usernames__

#### Dubsmash (dubsmash.com): 161749950 records breached [Verified breach]

Date: __2018-12-01__

In December 2018, the video messaging service [Dubsmash suffered a data breach](https://www.theregister.co.uk/2019/02/11/620_million_hacked_accounts_dark_web/). The incident exposed 162 million unique email addresses alongside usernames and PBKDF2 password hashes. In 2019, the data appeared listed for sale on a dark web marketplace (along with several other large breaches) and subsequently began circulating more broadly. The data was provided to HIBP by a source who requested it to be attributed to &quot;BenjaminBlue@exploit.im&quot;.
Data breached: __Email addresses,Geographic locations,Names,Passwords,Phone numbers,Spoken languages,Usernames__

#### Modern Business Solutions (modbsolutions.com): 58843488 records breached [Verified breach]

Date: __2016-10-08__

In October 2016, a large Mongo DB file containing tens of millions of accounts [was shared publicly on Twitter](https://twitter.com/0x2Taylor/status/784544208879292417) (the file has since been removed). The database contained over 58M unique email addresses along with IP addresses, names, home addresses, genders, job titles, dates of birth and phone numbers. The data was subsequently [attributed to &quot;Modern Business Solutions&quot;](http://news.softpedia.com/news/hacker-steals-58-million-user-records-from-data-storage-provider-509190.shtml), a company that provides data storage and database hosting solutions. They've yet to acknowledge the incident or explain how they came to be in possession of the data.
Data breached: __Dates of birth,Email addresses,Genders,IP addresses,Job titles,Names,Phone numbers,Physical addresses__

#### Straffic (straffic.io): 48580249 records breached [Verified breach]

Date: __2020-02-14__

In February 2020, Israeli marketing company [Straffic exposed a database with 140GB of personal data](https://www.databreachtoday.com/israeli-marketing-company-exposes-contacts-database-a-13785). The publicly accessible Elasticsearch database contained over 300M rows with 49M unique email addresses. Exposed data also included names, phone numbers, physical addresses and genders. In [their breach disclosure message](https://straffic.io/updates.php), Straffic stated that &quot;it is impossible to create a totally immune system, and these things can occur&quot;.
Data breached: __Email addresses,Genders,Names,Phone numbers,Physical addresses__

#### TestGame (zynga.com): 172869660 records breached [Verified breach]

Date: __2019-09-01__

In September 2019, game developer [TestGame (the creator of Words with Friends) suffered a data breach](https://www.cnet.com/news/words-with-friends-hack-reportedly-exposes-data-of-more-than-200m-players/). The incident exposed 173M unique email addresses alongside usernames and passwords stored as salted SHA-1 hashes. The data was provided to HIBP by [dehashed.com](https://dehashed.com/).
Data breached: __Email addresses,Passwords,Phone numbers,Usernames__

### 4. domain

---
Checks if a domain was compromised.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

##### Base Command

`domain`

##### Input

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| domain | Comma-separated list of domains to check. | Required |

##### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Domain.Pwned-V2.Compromised.Vendor | String | For compromised domains, the vendor that made the decision. |
| Domain.Pwned-V2.Compromised.Reporters | String | For compromised domains, the reporters for the vendor to make the compromised decision. |
| Domain.Name | String | The domain name. |
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. |
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | Vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

##### Command Example

```!domain domain="adobe.com"```

##### Context Example

```
{
    "Domain": {
        "Pwned-V2": {
            "Compromised": {
                "Vendor": "Have I Been Pwned? V2", 
                "Reporters": "Adobe"
            }
        }, 
        "Name": "adobe.com"
    }, 
    "DBotScore": {
        "Vendor": "Have I Been Pwned? V2", 
        "Indicator": "adobe.com", 
        "Score": 2, 
        "Type": "domain"
    }
}
```

##### Human Readable Output

### Have I Been Pwned query for domain: *adobe.com*

#### Adobe (adobe.com): 152445165 records breached [Verified breach]

Date: __2013-10-04__

In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and [many were quickly resolved back to plain text](http://stricture-group.com/files/adobe-top100.txt). The unencrypted hints also [disclosed much about the passwords](http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html) adding further to the risk that hundreds of millions of Adobe customers already faced.
Data breached: __Email addresses,Password hints,Passwords,Usernames__

### 5. pwned-username

---
Checks if a username was compromised.

##### Base Command

`pwned-username`

##### Input

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| username | Comma-separated list of usernames to check. | Required |

##### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Username.Pwned-V2.Compromised.Vendor | String | For compromised usernames, the vendor that made the decision. |
| Username.Pwned-V2.Compromised.Reporters | String | For compromised usernames, the reporters for the vendor to make the compromised decision. |
| Username.Name | String | The username name. |
| Username.Malicious.Vendor | String | For malicious usernames, the vendor that made the decision. |
| Username.Malicious.Description | String | For malicious usernames, the reason that the vendor made the decision. |

##### Command Example

```!pwned-username username="jondon"```

##### Context Example

```
{
    "Domain": {
        "Pwned-V2": {
            "Compromised": {
                "Vendor": "Have I Been Pwned? V2", 
                "Reporters": "Gawker, hackforums.net"
            }
        }, 
        "Name": "jondon"
    }, 
    "DBotScore": {
        "Vendor": "Have I Been Pwned? V2", 
        "Indicator": "jondon", 
        "Score": 2, 
        "Type": "domain"
    }
}
```

##### Human Readable Output

### Have I Been Pwned query for username: *jondon*

#### Gawker (gawker.com): 1247574 records breached [Verified breach]

Date: __2010-12-11__

In December 2010, Gawker was attacked by the hacker collective &quot;Gnosis&quot; in retaliation for what was reported to be a feud between Gawker and 4Chan. Information about Gawkers 1.3M users was published along with the data from Gawker's other web presences including Gizmodo and Lifehacker. Due to the prevalence of password reuse, many victims of the breach [then had their Twitter accounts compromised to send Acai berry spam](http://www.troyhunt.com/2011/01/why-your-apps-security-design-could.html).
Data breached: __Email addresses,Passwords,Usernames__

#### hackforums.net (hackforums.net): 191540 records breached [Verified breach]

Date: __2011-06-25__

In June 2011, the hacktivist group known as "LulzSec" leaked [one final large data breach they titled "50 days of lulz"](http://www.forbes.com/sites/andygreenberg/2011/06/25/lulzsec-says-goodbye-dumping-nato-att-gamer-data/). The compromised data came from sources such as AT&T, Battlefield Heroes and the [hackforums.net website](http://hackforums.net). The leaked Hack Forums data included credentials and personal information of nearly 200,000 registered forum users.
Data breached: __Dates of birth,Email addresses,Instant messenger identities,IP addresses,Passwords,Social connections,Spoken languages,Time zones,User website URLs,Usernames,Website activity__

### pwned-breaches-for-domain-list

***
Gets all breached email addresses for a domain.

#### Base Command

`pwned-breaches-for-domain-list`

#### Input

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| domain | Comma-separated list of domains to check for breaches. | Required |

#### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Domain.Pwned-V2.Breaches | Unknown | A dictionary of breached email aliases and their associated breach names for the domain. |

#### Command Example

```pwned-breaches-for-domain-list domain="adobe.com"```

### pwned-subscribed-domains-list

***
Gets the list of subscribed domains.

#### Base Command

`pwned-subscribed-domains-list`

#### Input

This command has no arguments.

#### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Pwned-V2.SubscribedDomain.DomainName | String | The full domain name that has been successfully verified. |
| Pwned-V2.SubscribedDomain.PwnCount | Number | Total number of breached email addresses found on the domain at last search. |
| Pwned-V2.SubscribedDomain.PwnCountExcludingSpamLists | Number | Number of breached email addresses found on the domain, excluding spam lists. |
| Pwned-V2.SubscribedDomain.PwnCountExcludingSpamListsAtLastSubscriptionRenewal | Number | Total breached email addresses found when the current subscription was taken out. |
| Pwned-V2.SubscribedDomain.NextSubscriptionRenewal | Date | The date and time the current subscription ends in ISO 8601 format. |

#### Command Example

```pwned-subscribed-domains-list```

### pwned-breach-get

***
Gets a single breached site by breach name.

#### Base Command

`pwned-breach-get`

#### Input

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| breach_name | The name of the breach to retrieve. | Required |

#### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Domain.Pwned-V2.Compromised.Vendor | String | For compromised domains, the vendor that made the decision. |
| Domain.Pwned-V2.Compromised.Reporters | String | For compromised domains, the reporters for the vendor to make the compromised decision. |
| Domain.Name | String | Domain name. |
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. |
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| Domain.Pwned-V2.AddedDate | Date | The date and time the breach was added to the system. |
| Domain.Pwned-V2.Attribution | String | The attribution of the breach. |
| Domain.Pwned-V2.BreachDate | Date | The date the breach occurred. |
| Domain.Pwned-V2.DataClasses | Unknown | The types of data that were compromised in the breach. |
| Domain.Pwned-V2.Description | String | A description of the breach. |
| Domain.Pwned-V2.DisclosureUrl | String | The URL where the breach was disclosed. |
| Domain.Pwned-V2.Domain | String | The domain of the breach. |
| Domain.Pwned-V2.IsFabricated | Boolean | Whether the breach is fabricated. |
| Domain.Pwned-V2.IsMalware | Boolean | Whether the breach is related to malware. |
| Domain.Pwned-V2.IsRetired | Boolean | Whether the breach is retired. |
| Domain.Pwned-V2.IsSensitive | Boolean | Whether the breach is sensitive. |
| Domain.Pwned-V2.IsSpamList | Boolean | Whether the breach is a spam list. |
| Domain.Pwned-V2.IsStealerLog | Boolean | Whether the breach is a stealer log. |
| Domain.Pwned-V2.IsSubscriptionFree | Boolean | Whether the breach is subscription free. |
| Domain.Pwned-V2.IsVerified | Boolean | Whether the breach is verified. |
| Domain.Pwned-V2.LogoPath | String | The path to the logo of the breach. |
| Domain.Pwned-V2.ModifiedDate | Date | The date and time the breach was last modified. |
| Domain.Pwned-V2.Name | String | The name of the breach. |
| Domain.Pwned-V2.PwnCount | Number | The number of accounts compromised in the breach. |
| Domain.Pwned-V2.Title | String | The title of the breach. |

#### Command Example

```!pwned-breach-get breach_name="Adobe"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "adobe.com",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "Have I Been Pwned? V2"
    },
    "Domain": {
        "Name": "adobe.com",
        "Pwned-V2": {
            "AddedDate": "2013-12-04T00:00:00Z",
            "Attribution": null,
            "BreachDate": "2013-10-04",
            "Compromised": {
                "Reporters": "Adobe",
                "Vendor": "Have I Been Pwned? V2"
            },
            "DataClasses": [
                "Email addresses",
                "Password hints",
                "Passwords",
                "Usernames"
            ],
            "Description": "In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and many were quickly resolved back to plain text. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\" rel=\"noopener\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced.",
            "DisclosureUrl": null,
            "Domain": "adobe.com",
            "IsFabricated": false,
            "IsMalware": false,
            "IsRetired": false,
            "IsSensitive": false,
            "IsSpamList": false,
            "IsStealerLog": false,
            "IsSubscriptionFree": false,
            "IsVerified": true,
            "LogoPath": "https://logos.haveibeenpwned.com/Adobe.png",
            "ModifiedDate": "2022-05-15T23:52:49Z",
            "Name": "Adobe",
            "PwnCount": 152445165,
            "Title": "Adobe"
        }
    }
}
```

#### Human Readable Output

>### Breach: Adobe

>|Latest breach domain name|Breach Date|Added Date|Pwn Count|
>|---|---|---|---|
>| adobe.com | 2013-10-04 | 2013-12-04T00:00:00Z | 152445165 |

### pwned-latest-breach-get

***
Gets the most recently added breach.

#### Base Command

`pwned-latest-breach-get`

#### Input

This command has no arguments.

#### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Domain.Pwned-V2.Compromised.Vendor | String | For compromised domains, the vendor that made the decision. |
| Domain.Pwned-V2.Compromised.Reporters | String | For compromised domains, the reporters for the vendor to make the compromised decision. |
| Domain.Name | String | Domain name. |
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. |
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| Domain.Pwned-V2.AddedDate | Date | The date and time the breach was added to the system. |
| Domain.Pwned-V2.Attribution | String | The attribution of the breach. |
| Domain.Pwned-V2.BreachDate | Date | The date the breach occurred. |
| Domain.Pwned-V2.DataClasses | Unknown | The types of data that were compromised in the breach. |
| Domain.Pwned-V2.Description | String | A description of the breach. |
| Domain.Pwned-V2.DisclosureUrl | String | The URL where the breach was disclosed. |
| Domain.Pwned-V2.Domain | String | The domain of the breach. |
| Domain.Pwned-V2.IsFabricated | Boolean | Whether the breach is fabricated. |
| Domain.Pwned-V2.IsMalware | Boolean | Whether the breach is related to malware. |
| Domain.Pwned-V2.IsRetired | Boolean | Whether the breach is retired. |
| Domain.Pwned-V2.IsSensitive | Boolean | Whether the breach is sensitive. |
| Domain.Pwned-V2.IsSpamList | Boolean | Whether the breach is a spam list. |
| Domain.Pwned-V2.IsStealerLog | Boolean | Whether the breach is a stealer log. |
| Domain.Pwned-V2.IsSubscriptionFree | Boolean | Whether the breach is subscription free. |
| Domain.Pwned-V2.IsVerified | Boolean | Whether the breach is verified. |
| Domain.Pwned-V2.LogoPath | String | The path to the logo of the breach. |
| Domain.Pwned-V2.ModifiedDate | Date | The date and time the breach was last modified. |
| Domain.Pwned-V2.Name | String | The name of the breach. |
| Domain.Pwned-V2.PwnCount | Number | The number of accounts compromised in the breach. |
| Domain.Pwned-V2.Title | String | The title of the breach. |

#### Command Example

```!pwned-latest-breach-get```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "hallmark.com",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "Have I Been Pwned? V2"
    },
    "Domain": {
        "Name": "hallmark.com",
        "Pwned-V2": {
            "AddedDate": "2026-04-12T02:01:11Z",
            "Attribution": null,
            "BreachDate": "2026-03-31",
            "Compromised": {
                "Reporters": "Hallmark",
                "Vendor": "Have I Been Pwned? V2"
            },
            "DataClasses": [
                "Email addresses",
                "Names",
                "Phone numbers",
                "Physical addresses",
                "Support tickets"
            ],
            "Description": "In March 2026, <a href=\"https://cybernews.com/security/hallmark-data-breach-shinyhunters/\" target=\"_blank\" rel=\"noopener\">Hallmark suffered an alleged breach and subsequent extortion</a> after attackers gained access to data stored within Salesforce. The data was later published after the extortion deadline passed, exposing 1.7M unique email addresses across both Hallmark and the Hallmark+ streaming service, along with names, phone numbers, physical addresses and support tickets.",
            "DisclosureUrl": null,
            "Domain": "hallmark.com",
            "IsFabricated": false,
            "IsMalware": false,
            "IsRetired": false,
            "IsSensitive": false,
            "IsSpamList": false,
            "IsStealerLog": false,
            "IsSubscriptionFree": false,
            "IsVerified": true,
            "LogoPath": "https://logos.haveibeenpwned.com/Hallmark.png",
            "ModifiedDate": "2026-04-12T02:01:11Z",
            "Name": "Hallmark",
            "PwnCount": 1736520,
            "Title": "Hallmark"
        }
    }
}
```

#### Human Readable Output

>### Latest Breach

>|Latest breach domain name|Breach Date|Added Date|Pwn Count|
>|---|---|---|---|
>| hallmark.com | 2026-03-31 | 2026-04-12T02:01:11Z | 1736520 |
