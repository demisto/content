Provides data enrichment for domains.
This integration was integrated and tested with version 1.0 of Whois

## Configure Whois in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Return Errors | If set, failed command results will be returned as warnings instead of errors. | False |
| Proxy URL | Supports socks4/socks5/http connect proxies \(e.g. socks5h://host:1080\). Will effect all commands except for the \`ip\` command. | False |
| Use system proxy settings | Effect the \`ip\` command and the other commands only if the Proxy URL is not set. | False |
| Use legacy context | Indicates whether to use the previous/legacy implementation of the integration commands and their outputs or the new ones. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Rate Limit Retry Count | The number of times to try when getting a Rate Limit response. | False |
| Rate Limit Wait Seconds | The number of seconds to wait between each iteration when getting a Rate Limit response. | False |
| Suppress Rate Limit errors | Whether Rate Limit errors should be supressed or not. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### whois
***
Provides data enrichment for domains.
This pack relies on free services for WHOIS information. As with many free services, the availability is not guaranteed. Free WHOIS providers may block or be reject queries.


#### Base Command

`whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The domain to enrich. | Required | 
| recursive | Whether to get the raw response from the whois servers recursively. Default value is True. | Optional | 
| verbose | Whether to add the raw response as a dictionary to the context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Score | string | The actual score. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Domain.Name | string | The domain name. | 
| Domain.DomainStatus | string | The domain status. | 
| Domain.Dnssec | string | The domain name system security extension \(DNSSEC\). | 
| Domain.NameServers | string | The name servers. | 
| Domain.Country | string | The domain country. | 
| Domain.State | string | The domain state. | 
| Domain.City | string | The domain city. | 
| Domain.CreationDate | date | The date that the domain was created \(UTC\). | 
| Domain.UpdatedDate | date | The date that the domain was last updated \(UTC\). | 
| Domain.ExpirationDate | date | The date that the domain expires \(UTC\). | 
| Domain.Registrar.Name | string | The name of the registrar. | 
| Domain.Registrar.Address | string | The address of the registrar. | 
| Domain.Registrar.Email | string | The email of the registrar. | 
| Domain.Registrar.Id | string | The ID of the registrar. | 
| Domain.Registrar.Phone | string | The phone number of the registrar. | 
| Domain.Registrar.Url | string | The URL of the registrar. | 
| Domain.Registrar.AbuseEmail | string | The email address of the contact for reporting abuse. | 
| Domain.Emails | string | The abuse emails. | 
| Domain.Address | string | The abuse address. | 
| Domain.Organization | string | The organization domain name. | 
| Domain.WhoisServer | string | The whois server name. | 
| Domain.Phone | string | The phone number of the tech administrator. | 
| Domain.Admin | object | Administrator information. | 
| Domain.Admin.Address | string | The address of the administrator. | 
| Domain.Admin.ApplicationPurpose | string | The application purpose of the administrator. | 
| Domain.Admin.C | string | The C field of the administrator. | 
| Domain.Admin.City | string | The city of the administrator. | 
| Domain.Admin.Country | string | The country of the administrator. | 
| Domain.Admin.Email | string | The email address of the administrator. | 
| Domain.Admin.Fax | string | The fax number of the administrator. | 
| Domain.Admin.FaxExt | string | The fax extension of the administrator. | 
| Domain.Admin.Id | string | The ID of the administrator. | 
| Domain.Admin.Name | string | The name of the administrator. | 
| Domain.Admin.Org | string | The organization of the administrator. | 
| Domain.Admin.Phone | string | The phone number of the administrator. | 
| Domain.Admin.PhoneExt | string | The phone extension of the administrator. | 
| Domain.Admin.PostalCode | string | The postal code of the administrator. | 
| Domain.Admin.State | string | The state of the administrator. | 
| Domain.Admin.StateProvince | string | The state or province of the administrator. | 
| Domain.Admin.Street | string | The street of the administrator. | 
| Domain.Registrant.Name | string | The name of the registrant. | 
| Domain.Registrant.Email | string | The email address of the registrant. | 
| Domain.Registrant.Country | string | The country of the registrant. | 
| Domain.Registrant.State | string | The state of the registrant. | 
| Domain.Registrant.Org | string | The organization of the registrant. | 
| Domain.Registrant.PostalCode | string | The postal code of the registrant. | 
| Domain.Registrant.Street | string | The street of the registrant. | 
| Domain.Registrant.Phone | string | The phone number of the registrant. | 
| Domain.Registrant.City | string | The city of the registrant. | 
| Domain.Registrant.Address | string | The address of the registrant. | 
| Domain.Registrant.ContactName | string | The contact name of the registrant. | 
| Domain.Registrant.Fax | string | The fax of the registrant. | 
| Domain.Registrant.Id | string | The ID of the registrant. | 
| Domain.Registrant.Number | string | The number of the registrant. | 
| Domain.Registrant.StateProvince | string | The state province of the registrant. | 
| Domain.Raw | string | The raw output from python-whois lib. | 
| Domain.Administrator | string | The country of the domain administrator. | 
| Domain.Tech.Name | string | The name of the tech contact. | 
| Domain.Tech.Address | string | The address of the tech contact. | 
| Domain.Tech.City | string | The city of the tech contact. | 
| Domain.Tech.Country | string | The country of the tech contact. | 
| Domain.Tech.Email | string | The email address of the tech contact. | 
| Domain.Tech.Fax | string | The fax number of the tech contact. | 
| Domain.Tech.ID | string | The ID of the tech contact. | 
| Domain.Tech.Organization | string | The organization of the tech contact. | 
| Domain.Tech.Phone | string | The phone number of the tech contact. | 
| Domain.Tech.PostalCode | string | The postal code of the tech contact. | 
| Domain.Tech.State | string | The state of the tech contact. | 
| Domain.Tech.StateProvince | string | The state/province of the tech contact. | 
| Domain.Tech.Street | string | The street of the tech contact. | 
| Domain.ID | string | The ID of the domain. | 
| Domain.WHOIS.Name | string | The domain name. | 
| Domain.WHOIS.DomainStatus | string | The domain status. | 
| Domain.WHOIS.Dnssec | string | The domain name system security extension \(DNSSEC\). | 
| Domain.WHOIS.NameServers | string | The name servers. | 
| Domain.WHOIS.Country | string | The domain country. | 
| Domain.WHOIS.State | string | The domain state. | 
| Domain.WHOIS.City | string | The domain city. | 
| Domain.WHOIS.CreationDate | date | The date that the domain was created \(UTC\). | 
| Domain.WHOIS.UpdatedDate | date | The date that the domain was last updated \(UTC\). | 
| Domain.WHOIS.ExpirationDate | date | The date that the domain expires \(UTC\). | 
| Domain.WHOIS.Registrar.Name | string | The name of the registrar. | 
| Domain.WHOIS.Registrar.Address | string | The address of the registrar. | 
| Domain.WHOIS.Registrar.Email | string | The email of the registrar. | 
| Domain.WHOIS.Registrar.Id | string | The ID of the registrar. | 
| Domain.WHOIS.Registrar.Phone | string | The phone number of the registrar. | 
| Domain.WHOIS.Registrar.Url | string | The URL of the registrar. | 
| Domain.WHOIS.Registrar.AbuseEmail | string | The email address of the contact for reporting abuse. | 
| Domain.WHOIS.Emails | string | The abuse emails. | 
| Domain.WHOIS.Address | string | The abuse address. | 
| Domain.WHOIS.Organization | string | The organization domain name. | 
| Domain.WHOIS.WhoisServer | string | The whois server name. | 
| Domain.WHOIS.Phone | string | The phone number of the tech administrator. | 
| Domain.WHOIS.Admin | object | Administrator information. | 
| Domain.WHOIS.Admin.Address | string | The address of the administrator. | 
| Domain.WHOIS.Admin.ApplicationPurpose | string | The application purpose of the administrator. | 
| Domain.WHOIS.Admin.C | string | The C field of the administrator. | 
| Domain.WHOIS.Admin.City | string | The city of the administrator. | 
| Domain.WHOIS.Admin.Country | string | The country of the administrator. | 
| Domain.WHOIS.Admin.Email | string | The email address of the administrator. | 
| Domain.WHOIS.Admin.Fax | string | The fax number of the administrator. | 
| Domain.WHOIS.Admin.FaxExt | string | The fax extension of the administrator. | 
| Domain.WHOIS.Admin.Id | string | The ID of the administrator. | 
| Domain.WHOIS.Admin.Name | string | The name of the administrator. | 
| Domain.WHOIS.Admin.Org | string | The organization of the administrator. | 
| Domain.WHOIS.Admin.Phone | string | The phone number of the administrator. | 
| Domain.WHOIS.Admin.PhoneExt | string | The phone extension of the administrator. | 
| Domain.WHOIS.Admin.PostalCode | string | The postal code of the administrator. | 
| Domain.WHOIS.Admin.State | string | The state of the administrator. | 
| Domain.WHOIS.Admin.StateProvince | string | The state or province of the administrator. | 
| Domain.WHOIS.Admin.Street | string | The street of the administrator. | 
| Domain.WHOIS.Registrant.Name | string | The name of the registrant. | 
| Domain.WHOIS.Registrant.Email | string | The email address of the registrant. | 
| Domain.WHOIS.Registrant.Country | string | The country of the registrant. | 
| Domain.WHOIS.Registrant.State | string | The state of the registrant. | 
| Domain.WHOIS.Registrant.Org | string | The organization of the registrant. | 
| Domain.WHOIS.Registrant.PostalCode | string | The postal code of the registrant. | 
| Domain.WHOIS.Registrant.Street | string | The street of the registrant. | 
| Domain.WHOIS.Registrant.Phone | string | The phone number of the registrant. | 
| Domain.WHOIS.Registrant.City | string | The city of the registrant. | 
| Domain.WHOIS.Registrant.Address | string | The address of the registrant. | 
| Domain.WHOIS.Registrant.ContactName | string | The contact name of the registrant. | 
| Domain.WHOIS.Registrant.Fax | string | The fax of the registrant. | 
| Domain.WHOIS.Registrant.Id | string | The ID of the registrant. | 
| Domain.WHOIS.Registrant.Number | string | The number of the registrant. | 
| Domain.WHOIS.Registrant.StateProvince | string | The state province of the registrant. | 
| Domain.WHOIS.Raw | string | The raw output from python-whois lib. | 
| Domain.WHOIS.Administrator | string | The country of the domain administrator. | 
| Domain.WHOIS.Tech.Name | string | The name of the tech contact. | 
| Domain.WHOIS.Tech.Address | string | The address of the tech contact. | 
| Domain.WHOIS.Tech.City | string | The city of the tech contact. | 
| Domain.WHOIS.Tech.Country | string | The country of the tech contact. | 
| Domain.WHOIS.Tech.Email | string | The email address of the tech contact. | 
| Domain.WHOIS.Tech.Fax | string | The fax number of the tech contact. | 
| Domain.WHOIS.Tech.ID | string | The ID of the tech contact. | 
| Domain.WHOIS.Tech.Org | string | The organization of the tech contact. | 
| Domain.WHOIS.Tech.Phone | string | The phone number of the tech contact. | 
| Domain.WHOIS.Tech.PostalCode | string | The postal code of the tech contact. | 
| Domain.WHOIS.Tech.State | string | The state of the tech contact. | 
| Domain.WHOIS.Tech.StateProvince | string | The state/province of the tech contact. | 
| Domain.WHOIS.Tech.Street | string | The street of the tech contact. | 
| Domain.WHOIS.ID | string | The ID of the domain. | 
| Domain.FeedRelatedIndicators.Type | String | Indicators that are associated with the domain. | 
| Domain.FeedRelatedIndicators.Value | String | The type of the indicators that are associated with the domain. | 
| Domain.WHOIS.FeedRelatedIndicators.Type | String | Indicators that are associated with the domain. | 
| Domain.WHOIS.FeedRelatedIndicators.Value | String | The type of the indicators that are associated with the domain. | 
| Domain.FeedRelatedIndicators.type | String | \(Legacy output\) Indicators that are associated with the domain. | 
| Domain.FeedRelatedIndicators.value | String | \(Legacy output\) The type of the indicators that are associated with the domain. | 
| Domain.Whois.Name | string | \(Legacy output\) The domain name. | 
| Domain.Whois.DomainStatus | string | \(Legacy output\) The domain status. | 
| Domain.Whois.DNSSec | string | \(Legacy output\) The domain name system security extension \(DNSSEC\). | 
| Domain.Whois.NameServers | string | \(Legacy output\) The name servers. | 
| Domain.Whois.CreationDate | date | \(Legacy output\) The date that the domain was created \(UTC\). | 
| Domain.Whois.UpdatedDate | date | \(Legacy output\)The date that the domain was last updated \(UTC\). | 
| Domain.Whois.ExpirationDate | date | \(Legacy output\)The date that the domain expires \(UTC\). | 
| Domain.Whois.Registrar.Name | string | \(Legacy output\)The name of the registrar. | 
| Domain.Whois.Emails | string | \(Legacy output\)The abuse emails. | 
| Domain.Whois.Registrar.AbuseEmail | string | \(Legacy output\) The email address of the contact for reporting abuse. | 
| Domain.Whois.Registrant.name | string | \(Legacy output\) The name of the registrant. | 
| Domain.Whois.Registrant.email | string | \(Legacy output\) The email address of the registrant. | 
| Domain.Whois.Raw | string | \(Legacy output\) The raw output. | 
| Domain.Whois.Administrator.country | string | \(Legacy output\) The country of the domain administrator. | 
| Domain.Whois.Administrator.name | string | \(Legacy output\) The name of the domain administrator. | 
| Domain.Whois.Administrator.state | string | \(Legacy output\) The state of the domain administrator. | 
| Domain.Whois.Administrator.email | string | \(Legacy output\) The email address of the domain administrator. | 
| Domain.Whois.Administrator.organization | string | \(Legacy output\) The organization of the domain administrator. | 
| Domain.Whois.Administrator.postalcode | string | \(Legacy output\) The postal code of the domain administrator. | 
| Domain.Whois.Administrator.street | string | \(Legacy output\) The street of the the domain admin. | 
| Domain.Whois.Administrator.phone | string | \(Legacy output\) The phone number of the domain administrator. | 
| Domain.Whois.Administrator.city | string | \(Legacy output\) The city of the domain administrator. | 
| Domain.Whois.TechAdmin.country | string | \(Legacy output\) The country of the tech administrator. | 
| Domain.Whois.TechAdmin.name | string | \(Legacy output\) The name of the tech administrator. | 
| Domain.Whois.TechAdmin.state | string | \(Legacy output\) The state of the tech administrator. | 
| Domain.Whois.TechAdmin.email | string | \(Legacy output\) The email address of the tech administrator. | 
| Domain.Whois.TechAdmin.organization | string | \(Legacy output\) The organization of the tech administrator. | 
| Domain.Whois.TechAdmin.postalcode | string | \(Legacy output\) The postal code of the tech administrator. | 
| Domain.Whois.TechAdmin.street | string | \(Legacy output\) The street of the tech administrator. | 
| Domain.Whois.TechAdmin.phone | string | \(Legacy output\) The phone number of the tech administrator. | 
| Domain.Whois.TechAdmin.city | string | \(Legacy output\) The city of the tech administrator. | 
| Domain.Whois.Registrant.country | string | \(Legacy output\) The country of the registrant. | 
| Domain.Whois.Registrant.state | string | \(Legacy output\) The state of the registrant. | 
| Domain.Whois.Registrant.organization | string | \(Legacy output\) The organization of the registrant. | 
| Domain.Whois.Registrant.postalcode | string | \(Legacy output\) The postal code of the registrant. | 
| Domain.Whois.Registrant.street | string | \(Legacy output\) The street of the registrant. | 
| Domain.Whois.Registrant.phone | string | \(Legacy output\) The phone number of the registrant. | 
| Domain.Whois.Registrant.city | string | \(Legacy output\) The city of the registrant. | 
| Domain.Whois.ID | string | \(Legacy output\) The ID of the domain. | 
| Domain.Whois.QueryStatus | string | \(Legacy output\) The result of the command \("Success" or "Failed"\). | 
| Domain.Whois.QueryValue | string | \(Legacy output\) The query requested by the user. | 
| Domain.Whois.QueryResult | Boolean | \(Legacy output\) Whether the query found a matching result. |  


#### Command example
```!whois query="paloaltonetworks.com"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "google.com",
        "Type": "domain",
        "Vendor": "Whois",
        "Score": 0,
        "Reliability": "B - Usually reliable"
    },
    "Domain": {
        "WHOIS": {
            "Name": "paloaltonetworks.com",
            "WhoisServer": "whois.markmonitor.com",
            "CreationDate": "21-02-2005",
            "ExpirationDate": "21-02-2026",
            "UpdatedDate": "08-02-2024",
            "Organization": "Palo Alto Networks, Inc.",
            "State": "CA",
            "Country": "US",
            "Dnssec": "signedDelegation",
            "Registrar": {
                "Name": "MarkMonitor, Inc."
            },
            "Emails": [
                "abusecomplaints@markmonitor.com",
                "whoisrequest@markmonitor.com"
            ],
            "NameServers": [
                "a1-184.akam.net",
                "a11-64.akam.net",
                "a12-67.akam.net",
                "a13-66.akam.net",
                "a2-65.akam.net",
                "a4-64.akam.net"
            ],
            "DomainStatus": [
                "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
                "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
                "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
                "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
                "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
                "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)"
            ],
            "FeedRelatedIndicators": [
                {
                    "Type": "email",
                    "Value": "abusecomplaints@markmonitor.com"
                },
                {
                    "Type": "email",
                    "Value": "whoisrequest@markmonitor.com"
                }
            ],
            "Raw": "domain_name: ['PALOALTONETWORKS.COM', 'paloaltonetworks.com'], registrar: MarkMonitor, Inc., whois_server: whois.markmonitor.com, referral_url: None, updated_date: [datetime.datetime(2024, 2, 8, 6, 27, 19), datetime.datetime(2024, 2, 8, 6, 27, 19, tzinfo=datetime.timezone.utc)], creation_date: [datetime.datetime(2005, 2, 21, 2, 42, 10), datetime.datetime(2005, 2, 21, 2, 42, 10, tzinfo=datetime.timezone.utc)], expiration_date: [datetime.datetime(2026, 2, 21, 2, 42, 10), datetime.datetime(2026, 2, 21, 0, 0, tzinfo=datetime.timezone.utc)], name_servers: ['A1-184.AKAM.NET', 'A11-64.AKAM.NET', 'A12-67.AKAM.NET', 'A13-66.AKAM.NET', 'A2-65.AKAM.NET', 'A4-64.AKAM.NET', 'a1-184.akam.net', 'a4-64.akam.net', 'a2-65.akam.net', 'a13-66.akam.net', 'a12-67.akam.net', 'a11-64.akam.net'], status: ['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited', 'clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)', 'clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)', 'clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)'], emails: ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'], dnssec: signedDelegation, name: None, org: Palo Alto Networks, Inc., address: None, city: None, state: CA, registrant_postal_code: None, country: US"
        },
        "Name": "paloaltonetworks.com",
        "WhoisServer": "whois.markmonitor.com",
        "CreationDate": "21-02-2005",
        "ExpirationDate": "21-02-2026",
        "UpdatedDate": "08-02-2024",
        "Organization": "Palo Alto Networks, Inc.",
        "State": "CA",
        "Country": "US",
        "Dnssec": "signedDelegation",
        "Registrar": {
            "Name": "MarkMonitor, Inc."
        },
        "Emails": [
            "abusecomplaints@markmonitor.com",
            "whoisrequest@markmonitor.com"
        ],
        "NameServers": [
            "a1-184.akam.net",
            "a11-64.akam.net",
            "a12-67.akam.net",
            "a13-66.akam.net",
            "a2-65.akam.net",
            "a4-64.akam.net"
        ],
        "DomainStatus": [
            "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
            "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
            "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
            "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)"
        ],
        "FeedRelatedIndicators": [
            {
                "Type": "email",
                "Value": "abusecomplaints@markmonitor.com"
            },
            {
                "Type": "email",
                "Value": "whoisrequest@markmonitor.com"
            }
        ],
        "Raw": "domain_name: ['PALOALTONETWORKS.COM', 'paloaltonetworks.com'], registrar: MarkMonitor, Inc., whois_server: whois.markmonitor.com, referral_url: None, updated_date: [datetime.datetime(2024, 2, 8, 6, 27, 19), datetime.datetime(2024, 2, 8, 6, 27, 19, tzinfo=datetime.timezone.utc)], creation_date: [datetime.datetime(2005, 2, 21, 2, 42, 10), datetime.datetime(2005, 2, 21, 2, 42, 10, tzinfo=datetime.timezone.utc)], expiration_date: [datetime.datetime(2026, 2, 21, 2, 42, 10), datetime.datetime(2026, 2, 21, 0, 0, tzinfo=datetime.timezone.utc)], name_servers: ['A1-184.AKAM.NET', 'A11-64.AKAM.NET', 'A12-67.AKAM.NET', 'A13-66.AKAM.NET', 'A2-65.AKAM.NET', 'A4-64.AKAM.NET', 'a1-184.akam.net', 'a4-64.akam.net', 'a2-65.akam.net', 'a13-66.akam.net', 'a12-67.akam.net', 'a11-64.akam.net'], status: ['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited', 'clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)', 'clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)', 'clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)'], emails: ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'], dnssec: signedDelegation, name: None, org: Palo Alto Networks, Inc., address: None, city: None, state: CA, registrant_postal_code: None, country: US"
    }
}
```

#### Human Readable Output

>### Whois results for paloaltonetworks.com
>|Name|CreationDate|ExpirationDate|UpdatedDate|NameServers|Organization|Registrar|DomainStatus|Emails|WhoisServer|
>|---|---|---|---|---|---|---|---|---|---|
>| paloaltonetworks.com | 21-02-2005 | 21-02-2026 | 08-02-2024 | a1-184.akam.net,<br>a11-64.akam.net,<br>a12-67.akam.net,<br>a13-66.akam.net,<br>a2-65.akam.net,<br>a4-64.akam.net | Palo Alto Networks, Inc. | Name: MarkMonitor, Inc. | clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited,<br>clientTransferProhibited https://icann.org/epp#clientTransferProhibited,<br>clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited,<br>clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited),<br>clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited),<br>clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited) | abusecomplaints@markmonitor.com,<br>whoisrequest@markmonitor.com | whois.markmonitor.com |

### domain
***
Provides data enrichment for domains.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to enrich. | Required | 
| recursive | Whether to get the raw response from the whois servers recursively. Default value is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Score | string | The actual score. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Domain.Name | string | The domain name. | 
| Domain.DomainStatus | String | The domain status. | 
| Domain.ExpirationDate | Date | The date that the domain expires \(UTC\). | 
| Domain.NameServers | String | The name servers. | 
| Domain.Organization | String | The organization name. | 
| Domain.ID | string | The ID of the domain. | 
| Domain.UpdatedDate | Date | The date that the domain was last updated \(UTC\). | 
| Domain.Dnssec | string | The domain name system security extension \(DNSSEC\). | 
| Domain.Country | string | The domain country. | 
| Domain.State | string | The domain state. | 
| Domain.City | string | The domain city. | 
| Domain.CreationDate | date | The date that the domain was created \(UTC\). | 
| Domain.Registrar.Name | string | The name of the registrar. | 
| Domain.Registrar.Address | string | The address of the registrar. | 
| Domain.Registrar.Email | string | The email of the registrar. | 
| Domain.Registrar.Id | string | The ID of the registrar. | 
| Domain.Registrar.Phone | string | The phone number of the registrar. | 
| Domain.Registrar.Url | string | The URL of the registrar. | 
| Domain.Registrar.AbuseEmail | string | The email address of the contact for reporting abuse. | 
| Domain.Emails | string | The abuse emails. | 
| Domain.Address | string | The abuse address. | 
| Domain.WhoisServer | string | The whois server name. | 
| Domain.Phone | string | The phone number of the tech administrator. | 
| Domain.Admin | object | Administrator information. | 
| Domain.Admin.Address | string | The address of the administrator. | 
| Domain.Admin.ApplicationPurpose | string | The application purpose of the administrator. | 
| Domain.Admin.C | string | The C field of the administrator. | 
| Domain.Admin.City | string | The city of the administrator. | 
| Domain.Admin.Country | string | The country of the administrator. | 
| Domain.Admin.Email | string | The email address of the administrator. | 
| Domain.Admin.Fax | string | The fax number of the administrator. | 
| Domain.Admin.FaxExt | string | The fax extension of the administrator. | 
| Domain.Admin.Id | string | The ID of the administrator. | 
| Domain.Admin.Name | string | The name of the administrator. | 
| Domain.Admin.Org | string | The organization of the administrator. | 
| Domain.Admin.Phone | string | The phone number of the administrator. | 
| Domain.Admin.PhoneExt | string | The phone extension of the administrator. | 
| Domain.Admin.PostalCode | string | The postal code of the administrator. | 
| Domain.Admin.State | string | The state of the administrator. | 
| Domain.Admin.StateProvince | string | The state or province of the administrator. | 
| Domain.Admin.Street | string | The street of the administrator. | 
| Domain.Registrant.Name | string | The name of the registrant. | 
| Domain.Registrant.Email | string | The email address of the registrant. | 
| Domain.Registrant.Country | string | The country of the registrant. | 
| Domain.Registrant.State | string | The state of the registrant. | 
| Domain.Registrant.Org | string | The organization of the registrant. | 
| Domain.Registrant.PostalCode | string | The postal code of the registrant. | 
| Domain.Registrant.Street | string | The street of the registrant. | 
| Domain.Registrant.Phone | string | The phone number of the registrant. | 
| Domain.Registrant.City | string | The city of the registrant. | 
| Domain.Registrant.Address | string | The address of the registrant. | 
| Domain.Registrant.ContactName | string | The contact name of the registrant. | 
| Domain.Registrant.Fax | string | The fax of the registrant. | 
| Domain.Registrant.Id | string | The ID of the registrant. | 
| Domain.Registrant.Number | string | The number of the registrant. | 
| Domain.Registrant.StateProvince | string | The state province of the registrant. | 
| Domain.Raw | string | The raw output from python-whois lib. | 
| Domain.Administrator | string | The country of the domain administrator. | 
| Domain.Tech.Name | string | The name of the tech contact. | 
| Domain.Tech.Address | string | The address of the tech contact. | 
| Domain.Tech.City | string | The city of the tech contact. | 
| Domain.Tech.Country | string | The country of the tech contact. | 
| Domain.Tech.Email | string | The email address of the tech contact. | 
| Domain.Tech.Fax | string | The fax number of the tech contact. | 
| Domain.Tech.ID | string | The ID of the tech contact. | 
| Domain.Tech.Org | string | The organization of the tech contact. | 
| Domain.Tech.Phone | string | The phone number of the tech contact. | 
| Domain.Tech.PostalCode | string | The postal code of the tech contact. | 
| Domain.Tech.State | string | The state of the tech contact. | 
| Domain.Tech.StateProvince | string | The state/province of the tech contact. | 
| Domain.Tech.Street | string | The street of the tech contact. | 
| Domain.FeedRelatedIndicators.Type | String | Indicators that are associated with the domain. | 
| Domain.FeedRelatedIndicators.Value | String | The type of the indicators that are associated with the domain. | 
| Domain.WHOIS.FeedRelatedIndicators.Type | String | Indicators that are associated with the domain. | 
| Domain.WHOIS.FeedRelatedIndicators.Value | String | The type of the indicators that are associated with the domain. | 
| Domain.WHOIS.Name | string | The domain name. | 
| Domain.WHOIS.ID | string | The ID of the domain. | 
| Domain.WHOIS.DomainStatus | string | The domain status. | 
| Domain.WHOIS.Dnssec | string | The domain name system security extension \(DNSSEC\). | 
| Domain.WHOIS.NameServers | string | The name servers. | 
| Domain.WHOIS.Country | string | The domain country. | 
| Domain.WHOIS.State | string | The domain state. | 
| Domain.WHOIS.City | string | The domain city. | 
| Domain.WHOIS.CreationDate | date | The date that the domain was created \(UTC\). | 
| Domain.WHOIS.UpdatedDate | date | The date that the domain was last updated \(UTC\). | 
| Domain.WHOIS.ExpirationDate | date | The date that the domain expires \(UTC\). | 
| Domain.WHOIS.Registrar.Name | string | The name of the registrar. | 
| Domain.WHOIS.Registrar.Address | string | The address of the registrar. | 
| Domain.WHOIS.Registrar.Email | string | The email of the registrar. | 
| Domain.WHOIS.Registrar.Id | string | The ID of the registrar. | 
| Domain.WHOIS.Registrar.Phone | string | The phone number of the registrar. | 
| Domain.WHOIS.Registrar.Url | string | The URL of the registrar. | 
| Domain.WHOIS.Registrar.AbuseEmail | string | The email address of the contact for reporting abuse. | 
| Domain.WHOIS.Emails | string | The abuse emails. | 
| Domain.WHOIS.Address | string | The abuse address. | 
| Domain.WHOIS.Organization | string | The organization domain name. | 
| Domain.WHOIS.WhoisServer | string | The whois server name. | 
| Domain.WHOIS.Phone | string | The phone number of the tech administrator. | 
| Domain.WHOIS.Admin | object | Administrator information. | 
| Domain.WHOIS.Admin.Address | string | The address of the administrator. | 
| Domain.WHOIS.Admin.ApplicationPurpose | string | The application purpose of the administrator. | 
| Domain.WHOIS.Admin.C | string | The C field of the administrator. | 
| Domain.WHOIS.Admin.City | string | The city of the administrator. | 
| Domain.WHOIS.Admin.Country | string | The country of the administrator. | 
| Domain.WHOIS.Admin.Email | string | The email address of the administrator. | 
| Domain.WHOIS.Admin.Fax | string | The fax number of the administrator. | 
| Domain.WHOIS.Admin.FaxExt | string | The fax extension of the administrator. | 
| Domain.WHOIS.Admin.Id | string | The ID of the administrator. | 
| Domain.WHOIS.Admin.Name | string | The name of the administrator. | 
| Domain.WHOIS.Admin.Org | string | The organization of the administrator. | 
| Domain.WHOIS.Admin.Phone | string | The phone number of the administrator. | 
| Domain.WHOIS.Admin.PhoneExt | string | The phone extension of the administrator. | 
| Domain.WHOIS.Admin.PostalCode | string | The postal code of the administrator. | 
| Domain.WHOIS.Admin.State | string | The state of the administrator. | 
| Domain.WHOIS.Admin.StateProvince | string | The state or province of the administrator. | 
| Domain.WHOIS.Admin.Street | string | The street of the administrator. | 
| Domain.WHOIS.Registrant.Name | string | The name of the registrant. | 
| Domain.WHOIS.Registrant.Email | string | The email address of the registrant. | 
| Domain.WHOIS.Registrant.Country | string | The country of the registrant. | 
| Domain.WHOIS.Registrant.State | string | The state of the registrant. | 
| Domain.WHOIS.Registrant.Org | string | The organization of the registrant. | 
| Domain.WHOIS.Registrant.PostalCode | string | The postal code of the registrant. | 
| Domain.WHOIS.Registrant.Street | string | The street of the registrant. | 
| Domain.WHOIS.Registrant.Phone | string | The phone number of the registrant. | 
| Domain.WHOIS.Registrant.City | string | The city of the registrant. | 
| Domain.WHOIS.Registrant.Address | string | The address of the registrant. | 
| Domain.WHOIS.Registrant.ContactName | string | The contact name of the registrant. | 
| Domain.WHOIS.Registrant.Fax | string | The fax of the registrant. | 
| Domain.WHOIS.Registrant.Id | string | The ID of the registrant. | 
| Domain.WHOIS.Registrant.Number | string | The number of the registrant. | 
| Domain.WHOIS.Registrant.StateProvince | string | The state province of the registrant. | 
| Domain.WHOIS.Raw | string | The raw output from python-whois lib. | 
| Domain.WHOIS.Administrator | string | The country of the domain administrator. | 
| Domain.WHOIS.Tech.Name | string | The name of the tech contact. | 
| Domain.WHOIS.Tech.Address | string | The address of the tech contact. | 
| Domain.WHOIS.Tech.City | string | The city of the tech contact. | 
| Domain.WHOIS.Tech.Country | string | The country of the tech contact. | 
| Domain.WHOIS.Tech.Email | string | The email address of the tech contact. | 
| Domain.WHOIS.Tech.Fax | string | The fax number of the tech contact. | 
| Domain.WHOIS.Tech.ID | string | The ID of the tech contact. | 
| Domain.WHOIS.Tech.Org | string | The organization of the tech contact. | 
| Domain.WHOIS.Tech.Phone | string | The phone number of the tech contact. | 
| Domain.WHOIS.Tech.PostalCode | string | The postal code of the tech contact. | 
| Domain.WHOIS.Tech.State | string | The state of the tech contact. | 
| Domain.WHOIS.Tech.StateProvince | string | The state/province of the tech contact. | 
| Domain.WHOIS.Tech.Street | string | The street of the tech contact. | 
| Domain.Whois.Name | string | \(Legacy output\) The domain name. | 
| Domain.Whois.DomainStatus | string | \(Legacy output\) The domain status. | 
| Domain.Whois.DNSSec | string | \(Legacy output\) The domain name system security extension \(DNSSEC\). | 
| Domain.Whois.NameServers | string | \(Legacy output\) The name servers. | 
| Domain.Whois.CreationDate | date | \(Legacy output\) The date that the domain was created \(UTC\). | 
| Domain.Whois.UpdatedDate | date | \(Legacy output\) The date that the domain was last updated \(UTC\). | 
| Domain.Whois.ExpirationDate | date | \(Legacy output\) The date that the domain expires \(UTC\). | 
| Domain.Whois.Registrar.Name | string | \(Legacy output\) The name of the registrar. | 
| Domain.Whois.Emails | string | \(Legacy output\) The abuse emails. | 
| Domain.Whois.Registrar.AbuseEmail | string | \(Legacy output\) The email address of the contact for reporting abuse. | 
| Domain.Whois.Registrant.name | string | \(Legacy output\) The name of the registrant. | 
| Domain.Whois.Registrant.email | string | \(Legacy output\) The email address of the registrant. | 
| Domain.Whois.Raw | string | \(Legacy output\) The raw output. | 
| Domain.Whois.Administrator.country | string | \(Legacy output\) The country of the domain administrator. | 
| Domain.Whois.Administrator.name | string | \(Legacy output\) The name of the domain administrator. | 
| Domain.Whois.Administrator.state | string | \(Legacy output\) The state of the domain administrator. | 
| Domain.Whois.Administrator.email | string | \(Legacy output\) The email address of the domain administrator. | 
| Domain.Whois.Administrator.organization | string | \(Legacy output\) The organization of the domain administrator. | 
| Domain.Whois.Administrator.postalcode | string | \(Legacy output\) The postal code of the domain administrator. | 
| Domain.Whois.Administrator.street | string | \(Legacy output\) The street of the domain administrator. | 
| Domain.Whois.Administrator.phone | string | \(Legacy output\) The phone number of the domain administrator. | 
| Domain.Whois.Administrator.city | string | \(Legacy output\) The city of the domain administrator. | 
| Domain.Whois.TechAdmin.country | string | \(Legacy output\) The country of the tech administrator. | 
| Domain.Whois.TechAdmin.name | string | \(Legacy output\) The name of the tech administrator. | 
| Domain.Whois.TechAdmin.state | string | \(Legacy output\) The state of the tech administrator. | 
| Domain.Whois.TechAdmin.email | string | \(Legacy output\) The email address of the tech administrator. | 
| Domain.Whois.TechAdmin.organization | string | \(Legacy output\) The organization of the tech administrator. | 
| Domain.Whois.TechAdmin.postalcode | string | \(Legacy output\) The postal code of the tech administrator. | 
| Domain.Whois.TechAdmin.street | string | \(Legacy output\) The street of the tech administrator. | 
| Domain.Whois.TechAdmin.phone | string | \(Legacy output\) The phone number of the tech administrator. | 
| Domain.Whois.TechAdmin.city | string | \(Legacy output\) The city of the tech administrator. | 
| Domain.Whois.Registrant.country | string | \(Legacy output\) The country of the registrant. | 
| Domain.Whois.Registrant.state | string | \(Legacy output\) The state of the registrant. | 
| Domain.Whois.Registrant.organization | string | \(Legacy output\) The organization of the registrant. | 
| Domain.Whois.Registrant.postalcode | string | \(Legacy output\) The postal code of the registrant. | 
| Domain.Whois.Registrant.street | string | \(Legacy output\) The street of the registrant. | 
| Domain.Whois.Registrant.phone | string | \(Legacy output\) The phone number of the registrant. | 
| Domain.Whois.Registrant.city | string | \(Legacy output\) The city of the registrant. | 
| Domain.Whois.ID | string | \(Legacy output\) The ID of the domain. | 
| Domain.Whois.QueryStatus | string | \(Legacy output\) The result of the command \("Success" or "Failed"\). | 
| Domain.Whois.QueryResult | Boolean | \(Legacy output\) Whether the query found a matching result. | 
| Domain.Admin.Country | String | \(Legacy output\) The country of the domain administrator. | 
| Domain.Admin.Name | String | \(Legacy output\) The name of domain administrator. | 
| Domain.Admin.State | String | \(Legacy output\) The state of domain administrator. | 
| Domain.Admin.country | String | \(Legacy output\) The country of the domain administrator. | 
| Domain.Admin.name | String | \(Legacy output\) The name of domain administrator. | 
| Domain.Admin.state | String | \(Legacy output\) The state of domain administrator. | 
| Domain.Registrant.country | String | \(Legacy output\) The country of the registrant. | 
| Domain.Registrant.organization | String | \(Legacy output\) The organization of the registrant. | 
| Domain.Registrant.state | String | \(Legacy output\) The state of the registrant. | 
| Domain.FeedRelatedIndicators.type | String | \(Legacy output\) Indicators that are associated with the domain. | 
| Domain.FeedRelatedIndicators.value | String | \(Legacy output\) The type of the indicators that are associated with the domain. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example
```!domain domain="google.com"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "google.com",
        "Type": "domain",
        "Vendor": "Whois",
        "Score": 0,
        "Reliability": "B - Usually reliable"
    },
    "Domain": {
        "WHOIS": {
            "Name": "google.com",
            "WhoisServer": "whois.markmonitor.com",
            "CreationDate": "15-09-1997",
            "ExpirationDate": "14-09-2028",
            "UpdatedDate": "09-09-2019",
            "Organization": "Google LLC",
            "State": "CA",
            "Country": "US",
            "Dnssec": "unsigned",
            "Registrar": {
                "Name": "MarkMonitor, Inc."
            },
            "Emails": [
                "abusecomplaints@markmonitor.com",
                "whoisrequest@markmonitor.com"
            ],
            "NameServers": [
                "ns1.google.com",
                "ns2.google.com",
                "ns3.google.com",
                "ns4.google.com"
            ],
            "DomainStatus": [
                "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
                "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
                "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
                "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
                "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
                "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited",
                "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
                "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
                "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
                "serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)",
                "serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)",
                "serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)"
            ],
            "FeedRelatedIndicators": [
                {
                    "Type": "email",
                    "Value": "abusecomplaints@markmonitor.com"
                },
                {
                    "Type": "email",
                    "Value": "whoisrequest@markmonitor.com"
                }
            ],
            "Raw": "domain_name: ['GOOGLE.COM', 'google.com'], registrar: MarkMonitor, Inc., whois_server: whois.markmonitor.com, referral_url: None, updated_date: [datetime.datetime(2019, 9, 9, 15, 39, 4), datetime.datetime(2019, 9, 9, 15, 39, 4, tzinfo=datetime.timezone.utc)], creation_date: [datetime.datetime(1997, 9, 15, 4, 0), datetime.datetime(1997, 9, 15, 7, 0, tzinfo=datetime.timezone.utc)], expiration_date: [datetime.datetime(2028, 9, 14, 4, 0), datetime.datetime(2028, 9, 13, 7, 0, tzinfo=datetime.timezone.utc)], name_servers: ['NS1.GOOGLE.COM', 'NS2.GOOGLE.COM', 'NS3.GOOGLE.COM', 'NS4.GOOGLE.COM', 'ns4.google.com', 'ns3.google.com', 'ns1.google.com', 'ns2.google.com'], status: ['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited', 'serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited', 'serverTransferProhibited https://icann.org/epp#serverTransferProhibited', 'serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited', 'clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)', 'clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)', 'clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)', 'serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)', 'serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)', 'serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)'], emails: ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'], dnssec: unsigned, name: None, org: Google LLC, address: None, city: None, state: CA, registrant_postal_code: None, country: US"
        },
        "Name": "google.com",
        "WhoisServer": "whois.markmonitor.com",
        "CreationDate": "15-09-1997",
        "ExpirationDate": "14-09-2028",
        "UpdatedDate": "09-09-2019",
        "Organization": "Google LLC",
        "State": "CA",
        "Country": "US",
        "Dnssec": "unsigned",
        "Registrar": {
            "Name": "MarkMonitor, Inc."
        },
        "Emails": [
            "abusecomplaints@markmonitor.com",
            "whoisrequest@markmonitor.com"
        ],
        "NameServers": [
            "ns1.google.com",
            "ns2.google.com",
            "ns3.google.com",
            "ns4.google.com"
        ],
        "DomainStatus": [
            "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
            "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
            "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
            "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited",
            "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
            "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
            "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
            "serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)",
            "serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)",
            "serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)"
        ],
        "FeedRelatedIndicators": [
            {
                "Type": "email",
                "Value": "abusecomplaints@markmonitor.com"
            },
            {
                "Type": "email",
                "Value": "whoisrequest@markmonitor.com"
            }
        ],
        "Raw": "domain_name: ['GOOGLE.COM', 'google.com'], registrar: MarkMonitor, Inc., whois_server: whois.markmonitor.com, referral_url: None, updated_date: [datetime.datetime(2019, 9, 9, 15, 39, 4), datetime.datetime(2019, 9, 9, 15, 39, 4, tzinfo=datetime.timezone.utc)], creation_date: [datetime.datetime(1997, 9, 15, 4, 0), datetime.datetime(1997, 9, 15, 7, 0, tzinfo=datetime.timezone.utc)], expiration_date: [datetime.datetime(2028, 9, 14, 4, 0), datetime.datetime(2028, 9, 13, 7, 0, tzinfo=datetime.timezone.utc)], name_servers: ['NS1.GOOGLE.COM', 'NS2.GOOGLE.COM', 'NS3.GOOGLE.COM', 'NS4.GOOGLE.COM', 'ns4.google.com', 'ns3.google.com', 'ns1.google.com', 'ns2.google.com'], status: ['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited', 'serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited', 'serverTransferProhibited https://icann.org/epp#serverTransferProhibited', 'serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited', 'clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)', 'clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)', 'clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)', 'serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)', 'serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)', 'serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)'], emails: ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'], dnssec: unsigned, name: None, org: Google LLC, address: None, city: None, state: CA, registrant_postal_code: None, country: US"
    }
}
```


#### Human Readable Output


>### Whois results for google.com
>|Name|CreationDate|ExpirationDate|UpdatedDate|NameServers|Organization|Registrar|DomainStatus|Emails|WhoisServer|
>|---|---|---|---|---|---|---|---|---|---|
>| google.com | 15-09-1997 | 14-09-2028 | 09-09-2019 | ns1.google.com,<br>ns2.google.com,<br>ns3.google.com,<br>ns4.google.com | Google LLC | Name: MarkMonitor, Inc. | clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited,<br>clientTransferProhibited https://icann.org/epp#clientTransferProhibited,<br>clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited,<br>serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited,<br>serverTransferProhibited https://icann.org/epp#serverTransferProhibited,<br>serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited,<br>clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited),<br>clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited),<br>clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited),<br>serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited),<br>serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited),<br>serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited) | abusecomplaints@markmonitor.com,<br>whoisrequest@markmonitor.com | whois.markmonitor.com |



### ip
***
Provides data enrichment for ips.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to enrich. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Whois.IP.asn | string | Globally unique identifier used for routing information exchange with Autonomous Systems. | 
| Whois.IP.asn_cidr | string | Network routing block assigned to an ASN. | 
| Whois.IP.asn_country_code | string | ASN assigned country code in ISO 3166-1 format. | 
| Whois.IP.asn_date | Date | ASN allocation date in ISO 8601 format. | 
| Whois.IP.asn_description | string | The ASN description | 
| Whois.IP.asn_registry | string | ASN assigned regional internet registry. | 
| Whois.IP.entities | string | list of object names referenced by an RIR network. Map these to the objects dictionary keys. | 
| Whois.IP.network.cidr | string | Network routing block an IP address belongs to. | 
| Whois.IP.network.country | string | Country code registered with the RIR in ISO 3166-1 format. | 
| Whois.IP.network.end_address | string | The last IP address in a network block. | 
| Whois.IP.network.events.action | string | The reason for an event. | 
| Whois.IP.network.events.actor | string | The identifier for an event initiator \(if any\). | 
| Whois.IP.network.events.timestamp | Date | The date an event occurred in ISO 8601 format. | 
| Whois.IP.network.handle | string | Unique identifier for a registered object. | 
| Whois.IP.network.ip_version | string | IP protocol version \(v4 or v6\) of an IP address. | 
| Whois.IP.network.links | string | HTTP/HTTPS links provided for an RIR object. | 
| Whois.IP.network.name | string | The identifier assigned to the network registration for an IP address. | 
| Whois.IP.network.notices.description | string | The description/body of a notice. | 
| Whois.IP.network.notices.links | string | list of HTTP/HTTPS links provided for a notice. | 
| Whois.IP.network.notices.title | string | The title/header for a notice. | 
| Whois.IP.network.parent_handle | string | Unique identifier for the parent network of a registered network. | 
| Whois.IP.network.remarks | string | List of remark \(notice\) dictionaries. | 
| Whois.IP.network.start_address | string | The first IP address in a network block. | 
| Whois.IP.network.status | string | List indicating the state of a registered object. | 
| Whois.IP.network.type | string | The RIR classification of a registered network. | 
| Whois.IP.query | string | The IP address | 
| IP.Address | string | IP address | 
| IP.ASN | string | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Geo.Country | string | The country in which the IP address is located. | 
| IP.Organization.Name | string | The organization name. | 
| IP.feed_related_indicators.value | string | Indicators that are associated with the IP. | 
| IP.feed_related_indicators.type | string | The type of the indicators that are associated with the IP | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example
```!ip ip=8.8.8.8```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Whois"
    },
    "IP": {
        "ASN": "15169",
        "Address": "8.8.8.8",
        "FeedRelatedIndicators": [
            {
                "description": null,
                "type": "CIDR",
                "value": "8.8.8.0/24"
            }
        ],
        "Organization": {
            "Name": "LVLT-GOGL-8-8-8"
        }
    },
    "Whois": {
        "IP": {
            "asn": "15169",
            "asn_cidr": "8.8.8.0/24",
            "asn_country_code": "US",
            "asn_date": "1992-12-01",
            "asn_description": "GOOGLE, US",
            "asn_registry": "arin",
            "entities": [
                "GOGL"
            ],
            "network": {
                "cidr": "8.8.8.0/24",
                "country": null,
                "end_address": "8.8.8.255",
                "events": [
                    {
                        "action": "last changed",
                        "actor": null,
                        "timestamp": "2014-03-14T16:52:05-04:00"
                    },
                    {
                        "action": "registration",
                        "actor": null,
                        "timestamp": "2014-03-14T16:52:05-04:00"
                    }
                ],
                "handle": "NET-8-8-8-0-1",
                "ip_version": "v4",
                "links": [
                    "https://rdap.arin.net/registry/ip/8.8.8.0",
                    "https://whois.arin.net/rest/net/NET-8-8-8-0-1",
                    "https://rdap.arin.net/registry/ip/8.0.0.0/9"
                ],
                "name": "LVLT-GOGL-8-8-8",
                "notices": [
                    {
                        "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                        "links": [
                            "https://www.arin.net/resources/registry/whois/tou/"
                        ],
                        "title": "Terms of Service"
                    },
                    {
                        "description": "If you see inaccuracies in the results, please visit: ",
                        "links": [
                            "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                        ],
                        "title": "Whois Inaccuracy Reporting"
                    },
                    {
                        "description": "Copyright 1997-2022, American Registry for Internet Numbers, Ltd.",
                        "links": null,
                        "title": "Copyright Notice"
                    }
                ],
                "parent_handle": "NET-8-0-0-0-1",
                "raw": null,
                "remarks": null,
                "start_address": "8.8.8.0",
                "status": [
                    "active"
                ],
                "type": "ALLOCATION"
            },
            "nir": null,
            "objects": {
                "ABUSE5250-ARIN": {
                    "contact": {
                        "address": [
                            {
                                "type": null,
                                "value": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                            }
                        ],
                        "email": [
                            {
                                "type": null,
                                "value": "network-abuse@google.com"
                            }
                        ],
                        "kind": "group",
                        "name": "Abuse",
                        "phone": [
                            {
                                "type": [
                                    "work",
                                    "voice"
                                ],
                                "value": "+1-650-253-0000"
                            }
                        ],
                        "role": null,
                        "title": null
                    },
                    "entities": null,
                    "events": [
                        {
                            "action": "last changed",
                            "actor": null,
                            "timestamp": "2018-10-24T11:23:55-04:00"
                        },
                        {
                            "action": "registration",
                            "actor": null,
                            "timestamp": "2015-11-06T15:36:35-05:00"
                        }
                    ],
                    "events_actor": null,
                    "handle": "ABUSE5250-ARIN",
                    "links": [
                        "https://rdap.arin.net/registry/entity/ABUSE5250-ARIN",
                        "https://whois.arin.net/rest/poc/ABUSE5250-ARIN"
                    ],
                    "notices": [
                        {
                            "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                            "links": [
                                "https://www.arin.net/resources/registry/whois/tou/"
                            ],
                            "title": "Terms of Service"
                        },
                        {
                            "description": "If you see inaccuracies in the results, please visit: ",
                            "links": [
                                "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                            ],
                            "title": "Whois Inaccuracy Reporting"
                        },
                        {
                            "description": "Copyright 1997-2022, American Registry for Internet Numbers, Ltd.",
                            "links": null,
                            "title": "Copyright Notice"
                        }
                    ],
                    "raw": null,
                    "remarks": [
                        {
                            "description": "Please note that the recommended way to file abuse complaints are located in the following links.\n\nTo report abuse and illegal activity: https://www.google.com/contact/\n\nFor legal requests: http://support.google.com/legal \n\nRegards,\nThe Google Team",
                            "links": null,
                            "title": "Registration Comments"
                        },
                        {
                            "description": "ARIN has attempted to validate the data for this POC, but has received no response from the POC since 2019-10-24",
                            "links": null,
                            "title": "Unvalidated POC"
                        }
                    ],
                    "roles": [
                        "abuse"
                    ],
                    "status": null
                },
                "GOGL": {
                    "contact": {
                        "address": [
                            {
                                "type": null,
                                "value": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                            }
                        ],
                        "email": null,
                        "kind": "org",
                        "name": "Google LLC",
                        "phone": null,
                        "role": null,
                        "title": null
                    },
                    "entities": [
                        "ABUSE5250-ARIN",
                        "ZG39-ARIN"
                    ],
                    "events": [
                        {
                            "action": "last changed",
                            "actor": null,
                            "timestamp": "2019-10-31T15:45:45-04:00"
                        },
                        {
                            "action": "registration",
                            "actor": null,
                            "timestamp": "2000-03-30T00:00:00-05:00"
                        }
                    ],
                    "events_actor": null,
                    "handle": "GOGL",
                    "links": [
                        "https://rdap.arin.net/registry/entity/GOGL",
                        "https://whois.arin.net/rest/org/GOGL"
                    ],
                    "notices": null,
                    "raw": null,
                    "remarks": [
                        {
                            "description": "Please note that the recommended way to file abuse complaints are located in the following links. \n\nTo report abuse and illegal activity: https://www.google.com/contact/\n\nFor legal requests: http://support.google.com/legal \n\nRegards, \nThe Google Team",
                            "links": null,
                            "title": "Registration Comments"
                        }
                    ],
                    "roles": [
                        "registrant"
                    ],
                    "status": null
                },
                "ZG39-ARIN": {
                    "contact": {
                        "address": [
                            {
                                "type": null,
                                "value": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                            }
                        ],
                        "email": [
                            {
                                "type": null,
                                "value": "arin-contact@google.com"
                            }
                        ],
                        "kind": "group",
                        "name": "Google LLC",
                        "phone": [
                            {
                                "type": [
                                    "work",
                                    "voice"
                                ],
                                "value": "+1-650-253-0000"
                            }
                        ],
                        "role": null,
                        "title": null
                    },
                    "entities": null,
                    "events": [
                        {
                            "action": "last changed",
                            "actor": null,
                            "timestamp": "2021-11-10T10:26:54-05:00"
                        },
                        {
                            "action": "registration",
                            "actor": null,
                            "timestamp": "2000-11-30T13:54:08-05:00"
                        }
                    ],
                    "events_actor": null,
                    "handle": "ZG39-ARIN",
                    "links": [
                        "https://rdap.arin.net/registry/entity/ZG39-ARIN",
                        "https://whois.arin.net/rest/poc/ZG39-ARIN"
                    ],
                    "notices": [
                        {
                            "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                            "links": [
                                "https://www.arin.net/resources/registry/whois/tou/"
                            ],
                            "title": "Terms of Service"
                        },
                        {
                            "description": "If you see inaccuracies in the results, please visit: ",
                            "links": [
                                "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                            ],
                            "title": "Whois Inaccuracy Reporting"
                        },
                        {
                            "description": "Copyright 1997-2022, American Registry for Internet Numbers, Ltd.",
                            "links": null,
                            "title": "Copyright Notice"
                        }
                    ],
                    "raw": null,
                    "remarks": null,
                    "roles": [
                        "technical",
                        "administrative"
                    ],
                    "status": [
                        "validated"
                    ]
                }
            },
            "query": "8.8.8.8",
            "raw": null
        }
    }
}
```

#### Human Readable Output

>### Whois results:
>|asn|asn_cidr|asn_date|country_code|network_name|query|
>|---|---|---|---|---|---|
>| 15169 | 8.8.8.0/24 | 1992-12-01 |  | LVLT-GOGL-8-8-8 | 8.8.8.8 |

## Troubleshooting
- The error message *Bad Gateway* (502) might occur when using a firewall/proxy. To fix the issue, make sure the whois TLD provider exists in your allowlist.
- 
## Known limitations
- The IP lookup has a rate limit of 1 lookup per second.