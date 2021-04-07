## Overview
---

Uses the Have I Been Pwned? service to check whether email addresses, domains, or usernames were compromised in previous breaches.

## Configure Have I Been Pwned? V2 on Demisto
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
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Comma-separated list of email addresses to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
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
                "Reporters": "Canva, Dubsmash, Modern Business Solutions, Straffic, Zynga"
            }
        }, 
        "Address": "michaljordan@gmail.com"
    }
}
```

##### Human Readable Output
### Have I Been Pwned query for email: *michaljordan@gmail.com*
#### Canva (canva.com): 137272116 records breached [Verified breach]
Date: **2019-05-24**

In May 2019, the graphic design tool website [Canva suffered a data breach](https://support.canva.com/contact/customer-support/may-24-security-incident-faqs/) that impacted 137 million subscribers. The exposed data included email addresses, usernames, names, cities of residence and passwords stored as bcrypt hashes for users not using social logins. The data was provided to HIBP by a source who requested it be attributed to "JimScott.Sec@protonmail.com".
Data breached: **Email addresses,Geographic locations,Names,Passwords,Usernames**
#### Dubsmash (dubsmash.com): 161749950 records breached [Verified breach]
Date: **2018-12-01**

In December 2018, the video messaging service [Dubsmash suffered a data breach](https://www.theregister.co.uk/2019/02/11/620_million_hacked_accounts_dark_web/). The incident exposed 162 million unique email addresses alongside usernames and PBKDF2 password hashes. In 2019, the data appeared listed for sale on a dark web marketplace (along with several other large breaches) and subsequently began circulating more broadly. The data was provided to HIBP by a source who requested it to be attributed to &quot;BenjaminBlue@exploit.im&quot;.
Data breached: **Email addresses,Geographic locations,Names,Passwords,Phone numbers,Spoken languages,Usernames**
#### Modern Business Solutions (modbsolutions.com): 58843488 records breached [Verified breach]
Date: **2016-10-08**

In October 2016, a large Mongo DB file containing tens of millions of accounts [was shared publicly on Twitter](https://twitter.com/0x2Taylor/status/784544208879292417) (the file has since been removed). The database contained over 58M unique email addresses along with IP addresses, names, home addresses, genders, job titles, dates of birth and phone numbers. The data was subsequently [attributed to &quot;Modern Business Solutions&quot;](http://news.softpedia.com/news/hacker-steals-58-million-user-records-from-data-storage-provider-509190.shtml), a company that provides data storage and database hosting solutions. They've yet to acknowledge the incident or explain how they came to be in possession of the data.
Data breached: **Dates of birth,Email addresses,Genders,IP addresses,Job titles,Names,Phone numbers,Physical addresses**
#### Straffic (straffic.io): 48580249 records breached [Verified breach]
Date: **2020-02-14**

In February 2020, Israeli marketing company [Straffic exposed a database with 140GB of personal data](https://www.databreachtoday.com/israeli-marketing-company-exposes-contacts-database-a-13785). The publicly accessible Elasticsearch database contained over 300M rows with 49M unique email addresses. Exposed data also included names, phone numbers, physical addresses and genders. In [their breach disclosure message](https://straffic.io/updates.php), Straffic stated that &quot;it is impossible to create a totally immune system, and these things can occur&quot;.
Data breached: **Email addresses,Genders,Names,Phone numbers,Physical addresses**
#### Zynga (zynga.com): 172869660 records breached [Verified breach]
Date: **2019-09-01**

In September 2019, game developer [Zynga (the creator of Words with Friends) suffered a data breach](https://www.cnet.com/news/words-with-friends-hack-reportedly-exposes-data-of-more-than-200m-players/). The incident exposed 173M unique email addresses alongside usernames and passwords stored as salted SHA-1 hashes. The data was provided to HIBP by [dehashed.com](https://dehashed.com/).
Data breached: **Email addresses,Passwords,Phone numbers,Usernames**


### 2. pwned-domain
---
Checks if a domain was compromised.
##### Base Command

`pwned-domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Comma-separated list of domains to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
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
Date: **2013-10-04**

In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and [many were quickly resolved back to plain text](http://stricture-group.com/files/adobe-top100.txt). The unencrypted hints also [disclosed much about the passwords](http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html) adding further to the risk that hundreds of millions of Adobe customers already faced.
Data breached: **Email addresses,Password hints,Passwords,Usernames**


### 3. email
---
Checks if an email address was compromised.
##### Base Command

`email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Comma-separated list of email addresses to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
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
                "Reporters": "Canva, Dubsmash, Modern Business Solutions, Straffic, Zynga"
            }
        }, 
        "Address": "michaljordan@gmail.com"
    }
}
```

##### Human Readable Output
### Have I Been Pwned query for email: *michaljordan@gmail.com*
#### Canva (canva.com): 137272116 records breached [Verified breach]
Date: **2019-05-24**

In May 2019, the graphic design tool website [Canva suffered a data breach](https://support.canva.com/contact/customer-support/may-24-security-incident-faqs/) that impacted 137 million subscribers. The exposed data included email addresses, usernames, names, cities of residence and passwords stored as bcrypt hashes for users not using social logins. The data was provided to HIBP by a source who requested it be attributed to "JimScott.Sec@protonmail.com".
Data breached: **Email addresses,Geographic locations,Names,Passwords,Usernames**
#### Dubsmash (dubsmash.com): 161749950 records breached [Verified breach]
Date: **2018-12-01**

In December 2018, the video messaging service [Dubsmash suffered a data breach](https://www.theregister.co.uk/2019/02/11/620_million_hacked_accounts_dark_web/). The incident exposed 162 million unique email addresses alongside usernames and PBKDF2 password hashes. In 2019, the data appeared listed for sale on a dark web marketplace (along with several other large breaches) and subsequently began circulating more broadly. The data was provided to HIBP by a source who requested it to be attributed to &quot;BenjaminBlue@exploit.im&quot;.
Data breached: **Email addresses,Geographic locations,Names,Passwords,Phone numbers,Spoken languages,Usernames**
#### Modern Business Solutions (modbsolutions.com): 58843488 records breached [Verified breach]
Date: **2016-10-08**

In October 2016, a large Mongo DB file containing tens of millions of accounts [was shared publicly on Twitter](https://twitter.com/0x2Taylor/status/784544208879292417) (the file has since been removed). The database contained over 58M unique email addresses along with IP addresses, names, home addresses, genders, job titles, dates of birth and phone numbers. The data was subsequently [attributed to &quot;Modern Business Solutions&quot;](http://news.softpedia.com/news/hacker-steals-58-million-user-records-from-data-storage-provider-509190.shtml), a company that provides data storage and database hosting solutions. They've yet to acknowledge the incident or explain how they came to be in possession of the data.
Data breached: **Dates of birth,Email addresses,Genders,IP addresses,Job titles,Names,Phone numbers,Physical addresses**
#### Straffic (straffic.io): 48580249 records breached [Verified breach]
Date: **2020-02-14**

In February 2020, Israeli marketing company [Straffic exposed a database with 140GB of personal data](https://www.databreachtoday.com/israeli-marketing-company-exposes-contacts-database-a-13785). The publicly accessible Elasticsearch database contained over 300M rows with 49M unique email addresses. Exposed data also included names, phone numbers, physical addresses and genders. In [their breach disclosure message](https://straffic.io/updates.php), Straffic stated that &quot;it is impossible to create a totally immune system, and these things can occur&quot;.
Data breached: **Email addresses,Genders,Names,Phone numbers,Physical addresses**
#### Zynga (zynga.com): 172869660 records breached [Verified breach]
Date: **2019-09-01**

In September 2019, game developer [Zynga (the creator of Words with Friends) suffered a data breach](https://www.cnet.com/news/words-with-friends-hack-reportedly-exposes-data-of-more-than-200m-players/). The incident exposed 173M unique email addresses alongside usernames and passwords stored as salted SHA-1 hashes. The data was provided to HIBP by [dehashed.com](https://dehashed.com/).
Data breached: **Email addresses,Passwords,Phone numbers,Usernames**


### 4. domain
---
Checks if a domain was compromised.
##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Comma-separated list of domains to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
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
Date: **2013-10-04**

In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and [many were quickly resolved back to plain text](http://stricture-group.com/files/adobe-top100.txt). The unencrypted hints also [disclosed much about the passwords](http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html) adding further to the risk that hundreds of millions of Adobe customers already faced.
Data breached: **Email addresses,Password hints,Passwords,Usernames**


### 5. pwned-username
---
Checks if a username was compromised.
##### Base Command

`pwned-username`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Comma-separated list of usernames to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
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
Date: **2010-12-11**

In December 2010, Gawker was attacked by the hacker collective &quot;Gnosis&quot; in retaliation for what was reported to be a feud between Gawker and 4Chan. Information about Gawkers 1.3M users was published along with the data from Gawker's other web presences including Gizmodo and Lifehacker. Due to the prevalence of password reuse, many victims of the breach [then had their Twitter accounts compromised to send Acai berry spam](http://www.troyhunt.com/2011/01/why-your-apps-security-design-could.html).
Data breached: **Email addresses,Passwords,Usernames**
#### hackforums.net (hackforums.net): 191540 records breached [Verified breach]
Date: **2011-06-25**

In June 2011, the hacktivist group known as "LulzSec" leaked [one final large data breach they titled "50 days of lulz"](http://www.forbes.com/sites/andygreenberg/2011/06/25/lulzsec-says-goodbye-dumping-nato-att-gamer-data/). The compromised data came from sources such as AT&T, Battlefield Heroes and the [hackforums.net website](http://hackforums.net). The leaked Hack Forums data included credentials and personal information of nearly 200,000 registered forum users.
Data breached: **Dates of birth,Email addresses,Instant messenger identities,IP addresses,Passwords,Social connections,Spoken languages,Time zones,User website URLs,Usernames,Website activity**
