Use the ViewDNS integration to enrich and pivot on domains, IP addresses, name servers, mail servers, and registrants with DNS, IP, and WHOIS intelligence from [ViewDNS.info](https://viewdns.info/api/).

This integration was developed against the ViewDNS.info API as documented at [https://viewdns.info/api/documentation/](https://viewdns.info/api/documentation/) (WHOIS v2 and Ping v2).

## Use cases

- Enrich a suspicious domain with its WHOIS record, historical hosting, and DNS records.
- Pivot from an attacker IP address to the other domains hosted on the same server (reverse IP).
- Pivot from a registrant name or email address to the other domains they registered (reverse WHOIS).
- Find the domains that share a name server or mail server.
- Check the remaining ViewDNS API queries from a playbook before running a costly pivot.

## Get an API key

1. Sign up for a ViewDNS.info account at [https://viewdns.info/api/](https://viewdns.info/api/).
2. Log in and copy the API key from your account dashboard.
3. The **viewdns-whois** and **viewdns-reverse-whois** commands, and the **domain** and **ip** reputation commands (which use WHOIS), require a paid API key.

## API query usage

ViewDNS plans include a monthly number of API queries, and prepaid queries can be added on top. Keep the following in mind:

- Every command consumes one API query for each call, except **viewdns-account-balance** and the instance **Test** button, which are free.
- Commands with a **page** argument consume one query for each page retrieved. The **limit** argument only controls how many results of that page are returned; it does not change the number of queries consumed.
- The generic **domain** and **ip** reputation commands are disabled by default. When **Enable reputation commands** is selected, every enriched indicator consumes two API queries. Because Cortex XSOAR can run reputation commands automatically on every extracted indicator, enable this option only if your ViewDNS plan can cover that volume.
- When the monthly quota is used up and no prepaid queries remain, commands fail with a "query limit was reached" error until the quota resets or more queries are purchased. The integration does not retry these requests.
- ViewDNS does not provide a verdict, so the reputation commands always return a DBot score of 0 (Unknown). Use them for context, not for scoring.

## Active commands

The **viewdns-port-scan**, **viewdns-ping**, and **viewdns-traceroute** commands make ViewDNS servers connect to the target host, which the owner of the target can notice. Use them with care and only on hosts you are permitted to probe. ViewDNS rejects private IP addresses for these commands.

## Configure ViewDNS in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ViewDNS.
3. Click **Add instance** to create and configure a new integration instance.
4. Click **Test** to validate the URL and API key. The test does not consume API queries.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of the ViewDNS API. | True |
| API Key | The API key of your ViewDNS.info account. | True |
| Enable reputation commands (consumes API credits on every indicator) | When selected, the generic domain and ip reputation commands query ViewDNS, consuming two API queries for every indicator enriched. When cleared, these commands return a message and consume nothing. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
The examples in this document show the output format using sample data from the ViewDNS.info API documentation.

### viewdns-account-balance

***
Retrieves the query usage and remaining balance of the ViewDNS API key. This command does not consume API queries.

#### Base Command

`viewdns-account-balance`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.Account.Plan | String | The plan type of the API key \(monthly or trial\). |
| ViewDNS.Account.MonthlyLimit | Number | The number of queries included in the plan per month. A value of 0 means the plan is unlimited. |
| ViewDNS.Account.MonthlyUsage | Number | The number of queries used in the current month. |
| ViewDNS.Account.MonthlyRemaining | Number | The number of plan queries remaining in the current month. Not returned for unlimited plans. |
| ViewDNS.Account.PrepaidBalance | Number | The number of prepaid queries remaining. |

#### Command example

```!viewdns-account-balance```

#### Context Example

```json
{
    "ViewDNS": {
        "Account": {
            "Plan": "monthly",
            "MonthlyLimit": 10000,
            "MonthlyUsage": 3197,
            "MonthlyRemaining": 6803,
            "PrepaidBalance": 2000
        }
    }
}
```

#### Human Readable Output

>### ViewDNS Account Balance
>
>|Plan|Monthly Limit|Monthly Usage|Monthly Remaining|Prepaid Balance|
>|---|---|---|---|---|
>| monthly | 10000 | 3197 | 6803 | 2000 |

### viewdns-reverse-ip

***
Finds the domains hosted on the same server as a given domain or IP address. Each call consumes one API query.

#### Base Command

`viewdns-reverse-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The domain or IP address to find co-hosted domains for. | Required |
| page | The page of API results to retrieve. Each page holds up to 10,000 results and each page retrieved consumes one API query. Default is 1. | Optional |
| limit | The maximum number of results to return from the retrieved page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.ReverseIP.Host | String | The domain or IP address that was searched for. |
| ViewDNS.ReverseIP.DomainCount | Number | The total number of domains hosted on the server. |
| ViewDNS.ReverseIP.Page | Number | The result page that was retrieved. |
| ViewDNS.ReverseIP.Domains.Name | String | A domain hosted on the server. |
| ViewDNS.ReverseIP.Domains.LastResolved | Date | The date the domain was last seen resolving to the server. |

#### Command example

```!viewdns-reverse-ip host=example.com limit=3```

#### Context Example

```json
{
    "ViewDNS": {
        "ReverseIP": {
            "Host": "example.com",
            "DomainCount": 5,
            "Page": 1,
            "Domains": [
                {
                    "Name": "atlabs.dev",
                    "LastResolved": "2024-09-28"
                },
                {
                    "Name": "example.com",
                    "LastResolved": "2024-10-02"
                },
                {
                    "Name": "example.edu",
                    "LastResolved": "2024-10-02"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS Reverse IP for example.com (showing 3 of 5, page 1)
>
>|Name|Last Resolved|
>|---|---|
>| atlabs.dev | 2024-09-28 |
>| example.com | 2024-10-02 |
>| example.edu | 2024-10-02 |

### viewdns-reverse-whois

***
Finds the domains registered by a given person or organization, searching by registrant name or email address. Requires a paid ViewDNS API key. Each call consumes one API query.

#### Base Command

`viewdns-reverse-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The registrant name or email address to search for. Must be at least five characters long. | Required |
| page | The page of API results to retrieve. Each page holds up to 1,000 results and each page retrieved consumes one API query. Default is 1. | Optional |
| limit | The maximum number of results to return from the retrieved page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.ReverseWhois.Query | String | The registrant name or email address that was searched for. |
| ViewDNS.ReverseWhois.ResultCount | Number | The total number of matching domains. |
| ViewDNS.ReverseWhois.TotalPages | Number | The total number of result pages available. |
| ViewDNS.ReverseWhois.CurrentPage | Number | The result page that was retrieved. |
| ViewDNS.ReverseWhois.Matches.Domain | String | A domain that matches the search. |
| ViewDNS.ReverseWhois.Matches.CreatedDate | Date | The date the domain was registered. |
| ViewDNS.ReverseWhois.Matches.Registrar | String | The registrar of the domain. |

#### Command example

```!viewdns-reverse-whois query=domain@example.com limit=3```

#### Context Example

```json
{
    "ViewDNS": {
        "ReverseWhois": {
            "Query": "domain@example.com",
            "ResultCount": 4,
            "TotalPages": 1,
            "CurrentPage": 1,
            "Matches": [
                {
                    "Domain": "atheismfacts.org",
                    "CreatedDate": "2012-08-03",
                    "Registrar": "NAME.COM, LLC"
                },
                {
                    "Domain": "chibrary.com",
                    "CreatedDate": "2011-11-13",
                    "Registrar": "NAME.COM, INC."
                },
                {
                    "Domain": "push.cx",
                    "CreatedDate": "2003-04-24",
                    "Registrar": "NAME.COM LLC"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS Reverse WHOIS for domain@example.com (showing 3 of 4, page 1)
>
>|Domain|Created Date|Registrar|
>|---|---|---|
>| atheismfacts.org | 2012-08-03 | NAME.COM, LLC |
>| chibrary.com | 2011-11-13 | NAME.COM, INC. |
>| push.cx | 2003-04-24 | NAME.COM LLC |

### viewdns-ip-history

***
Retrieves the IP addresses a domain has been hosted on over time. Only registered domains are tracked, not subdomains. Each call consumes one API query.

#### Base Command

`viewdns-ip-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to retrieve the IP history of, for example example.com. | Required |
| limit | The maximum number of records to return, starting from the most recent. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.IPHistory.Domain | String | The domain that was searched for. |
| ViewDNS.IPHistory.RecordCount | Number | The total number of historical records available for the domain. |
| ViewDNS.IPHistory.Records.IP | String | An IP address the domain was hosted on. |
| ViewDNS.IPHistory.Records.Location | String | The location of the IP address. |
| ViewDNS.IPHistory.Records.Owner | String | The owner of the IP address. |
| ViewDNS.IPHistory.Records.LastSeen | Date | The date the domain was last seen on the IP address. |

#### Command example

```!viewdns-ip-history domain=domain.com limit=3```

#### Context Example

```json
{
    "ViewDNS": {
        "IPHistory": {
            "Domain": "domain.com",
            "RecordCount": 4,
            "Records": [
                {
                    "IP": "172.64.145.59",
                    "Location": "Unknown",
                    "Owner": "Cloudflare, Inc",
                    "LastSeen": "2024-09-20"
                },
                {
                    "IP": "104.18.42.197",
                    "Location": "Unknown",
                    "Owner": "Cloudflare, Inc",
                    "LastSeen": "2024-09-20"
                },
                {
                    "IP": "65.254.244.180",
                    "Location": "United States",
                    "Owner": "BIZLAND-SD",
                    "LastSeen": "2015-12-15"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS IP History for domain.com (showing 3 of 4)
>
>|IP|Location|Owner|Last Seen|
>|---|---|---|---|
>| 172.64.145.59 | Unknown | Cloudflare, Inc | 2024-09-20 |
>| 104.18.42.197 | Unknown | Cloudflare, Inc | 2024-09-20 |
>| 65.254.244.180 | United States | BIZLAND-SD | 2015-12-15 |

### viewdns-dns-record

***
Retrieves the DNS records of a domain or hostname. Each call consumes one API query.

#### Base Command

`viewdns-dns-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain or hostname to retrieve DNS records for. | Required |
| record_type | The type of DNS record to retrieve. Other valid DNS record types can also be entered. Possible values are: ANY, A, AAAA, CAA, CNAME, DNSKEY, DS, MX, NS, PTR, SOA, SRV, TXT. Default is ANY. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.DNSRecord.Domain | String | The domain or hostname that was searched for. |
| ViewDNS.DNSRecord.RecordType | String | The record type that was requested. |
| ViewDNS.DNSRecord.Records.Name | String | The name of the record. |
| ViewDNS.DNSRecord.Records.TTL | Number | The time to live of the record, in seconds. |
| ViewDNS.DNSRecord.Records.Class | String | The class of the record. |
| ViewDNS.DNSRecord.Records.Type | String | The type of the record. |
| ViewDNS.DNSRecord.Records.Priority | Number | The priority of the record \(MX records only\). |
| ViewDNS.DNSRecord.Records.Data | String | The data of the record. |

#### Command example

```!viewdns-dns-record domain=domain.com record_type=ANY```

#### Context Example

```json
{
    "ViewDNS": {
        "DNSRecord": {
            "Domain": "domain.com",
            "RecordType": "ANY",
            "Records": [
                {
                    "Name": "domain.com.",
                    "TTL": 1800,
                    "Class": "IN",
                    "Type": "SOA",
                    "Data": "lee.ns.cloudflare.com. dns.cloudflare.com. 2352199173 10000 2400 604800 1800"
                },
                {
                    "Name": "domain.com.",
                    "TTL": 86400,
                    "Class": "IN",
                    "Type": "NS",
                    "Data": "lee.ns.cloudflare.com."
                },
                {
                    "Name": "domain.com.",
                    "TTL": 300,
                    "Class": "IN",
                    "Type": "A",
                    "Data": "172.64.145.59"
                },
                {
                    "Name": "domain.com.",
                    "TTL": 300,
                    "Class": "IN",
                    "Type": "TXT",
                    "Data": "\"v=spf1 include:spf.protection.outlook.com -all\""
                },
                {
                    "Name": "domain.com.",
                    "TTL": 300,
                    "Class": "IN",
                    "Type": "MX",
                    "Priority": 10,
                    "Data": "domain-com.mail.protection.outlook.com."
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS DNS Records for domain.com (ANY)
>
>|Name|Type|TTL|Class|Priority|Data|
>|---|---|---|---|---|---|
>| domain.com. | SOA | 1800 | IN |  | lee.ns.cloudflare.com. dns.cloudflare.com. 2352199173 10000 2400 604800 1800 |
>| domain.com. | NS | 86400 | IN |  | lee.ns.cloudflare.com. |
>| domain.com. | A | 300 | IN |  | 172.64.145.59 |
>| domain.com. | TXT | 300 | IN |  | "v=spf1 include:spf.protection.outlook.com -all" |
>| domain.com. | MX | 300 | IN | 10 | domain-com.mail.protection.outlook.com. |

### viewdns-whois

***
Retrieves the WHOIS record of a domain or IP address. Requires a paid ViewDNS API key. Each call consumes one API query.

#### Base Command

`viewdns-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain or IP address to retrieve the WHOIS record of. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.Whois.DomainName | String | The domain name. |
| ViewDNS.Whois.RegistrarName | String | The name of the registrar. |
| ViewDNS.Whois.RegistrarIANAID | String | The IANA ID of the registrar. |
| ViewDNS.Whois.CreatedDate | Date | The date the domain was registered. |
| ViewDNS.Whois.UpdatedDate | Date | The date the domain registration was last updated. |
| ViewDNS.Whois.ExpiresDate | Date | The date the domain registration expires. |
| ViewDNS.Whois.AbuseEmail | String | The abuse contact email address. |
| ViewDNS.Whois.Registrant.Name | String | The name of the registrant. |
| ViewDNS.Whois.Registrant.Organization | String | The organization of the registrant. |
| ViewDNS.Whois.Registrant.Street | String | The street address of the registrant. |
| ViewDNS.Whois.Registrant.City | String | The city of the registrant. |
| ViewDNS.Whois.Registrant.State | String | The state or province of the registrant. |
| ViewDNS.Whois.Registrant.PostalCode | String | The postal code of the registrant. |
| ViewDNS.Whois.Registrant.Country | String | The country of the registrant. |
| ViewDNS.Whois.Registrant.Phone | String | The phone number of the registrant. |
| ViewDNS.Whois.Registrant.Fax | String | The fax number of the registrant. |
| ViewDNS.Whois.Registrant.Email | String | The email address of the registrant. |
| ViewDNS.Whois.Admin.Name | String | The name of the administrative contact. |
| ViewDNS.Whois.Admin.Organization | String | The organization of the administrative contact. |
| ViewDNS.Whois.Admin.Street | String | The street address of the administrative contact. |
| ViewDNS.Whois.Admin.City | String | The city of the administrative contact. |
| ViewDNS.Whois.Admin.State | String | The state or province of the administrative contact. |
| ViewDNS.Whois.Admin.PostalCode | String | The postal code of the administrative contact. |
| ViewDNS.Whois.Admin.Country | String | The country of the administrative contact. |
| ViewDNS.Whois.Admin.Phone | String | The phone number of the administrative contact. |
| ViewDNS.Whois.Admin.Fax | String | The fax number of the administrative contact. |
| ViewDNS.Whois.Admin.Email | String | The email address of the administrative contact. |
| ViewDNS.Whois.Tech.Name | String | The name of the technical contact. |
| ViewDNS.Whois.Tech.Organization | String | The organization of the technical contact. |
| ViewDNS.Whois.Tech.Street | String | The street address of the technical contact. |
| ViewDNS.Whois.Tech.City | String | The city of the technical contact. |
| ViewDNS.Whois.Tech.State | String | The state or province of the technical contact. |
| ViewDNS.Whois.Tech.PostalCode | String | The postal code of the technical contact. |
| ViewDNS.Whois.Tech.Country | String | The country of the technical contact. |
| ViewDNS.Whois.Tech.Phone | String | The phone number of the technical contact. |
| ViewDNS.Whois.Tech.Fax | String | The fax number of the technical contact. |
| ViewDNS.Whois.Tech.Email | String | The email address of the technical contact. |
| ViewDNS.Whois.NameServers | String | The name servers of the domain. |
| ViewDNS.Whois.Status | String | The EPP status codes of the domain. |
| ViewDNS.Whois.RawText | String | The raw WHOIS record. |
| ViewDNS.IPWhois.IP | String | The IP address. |
| ViewDNS.IPWhois.Registry | String | The regional internet registry that holds the record. |
| ViewDNS.IPWhois.Owner | String | The owner of the network. |
| ViewDNS.IPWhois.NetName | String | The name of the network. |
| ViewDNS.IPWhois.NetRange | String | The address range of the network. |
| ViewDNS.IPWhois.CIDR | String | The network in CIDR notation. |
| ViewDNS.IPWhois.ASN | String | The autonomous system number of the network, when available. |
| ViewDNS.IPWhois.Country | String | The country of the network. |
| ViewDNS.IPWhois.CreatedDate | Date | The date the network was registered. |
| ViewDNS.IPWhois.UpdatedDate | Date | The date the network registration was last updated. |
| ViewDNS.IPWhois.Abuse.Name | String | The name of the abuse contact. |
| ViewDNS.IPWhois.Abuse.Organization | String | The organization of the abuse contact. |
| ViewDNS.IPWhois.Abuse.Street | String | The street address of the abuse contact. |
| ViewDNS.IPWhois.Abuse.City | String | The city of the abuse contact. |
| ViewDNS.IPWhois.Abuse.State | String | The state or province of the abuse contact. |
| ViewDNS.IPWhois.Abuse.PostalCode | String | The postal code of the abuse contact. |
| ViewDNS.IPWhois.Abuse.Country | String | The country of the abuse contact. |
| ViewDNS.IPWhois.Abuse.Phone | String | The phone number of the abuse contact. |
| ViewDNS.IPWhois.Abuse.Fax | String | The fax number of the abuse contact. |
| ViewDNS.IPWhois.Abuse.Email | String | The email address of the abuse contact. |
| ViewDNS.IPWhois.Admin.Name | String | The name of the administrative contact. |
| ViewDNS.IPWhois.Admin.Organization | String | The organization of the administrative contact. |
| ViewDNS.IPWhois.Admin.Street | String | The street address of the administrative contact. |
| ViewDNS.IPWhois.Admin.City | String | The city of the administrative contact. |
| ViewDNS.IPWhois.Admin.State | String | The state or province of the administrative contact. |
| ViewDNS.IPWhois.Admin.PostalCode | String | The postal code of the administrative contact. |
| ViewDNS.IPWhois.Admin.Country | String | The country of the administrative contact. |
| ViewDNS.IPWhois.Admin.Phone | String | The phone number of the administrative contact. |
| ViewDNS.IPWhois.Admin.Fax | String | The fax number of the administrative contact. |
| ViewDNS.IPWhois.Admin.Email | String | The email address of the administrative contact. |
| ViewDNS.IPWhois.Tech.Name | String | The name of the technical contact. |
| ViewDNS.IPWhois.Tech.Organization | String | The organization of the technical contact. |
| ViewDNS.IPWhois.Tech.Street | String | The street address of the technical contact. |
| ViewDNS.IPWhois.Tech.City | String | The city of the technical contact. |
| ViewDNS.IPWhois.Tech.State | String | The state or province of the technical contact. |
| ViewDNS.IPWhois.Tech.PostalCode | String | The postal code of the technical contact. |
| ViewDNS.IPWhois.Tech.Country | String | The country of the technical contact. |
| ViewDNS.IPWhois.Tech.Phone | String | The phone number of the technical contact. |
| ViewDNS.IPWhois.Tech.Fax | String | The fax number of the technical contact. |
| ViewDNS.IPWhois.Tech.Email | String | The email address of the technical contact. |
| ViewDNS.IPWhois.Status | String | The status of the network registration. |
| ViewDNS.IPWhois.RawText | String | The raw WHOIS record. |

#### Command example

```!viewdns-whois domain=domain.com```

#### Context Example

```json
{
    "ViewDNS": {
        "Whois": {
            "RegistrarName": "Domain.com, LLC",
            "RegistrarIANAID": "886",
            "CreatedDate": "1994-07-01T04:00:00Z",
            "UpdatedDate": "2024-01-22T21:36:01Z",
            "ExpiresDate": "2031-01-07T13:34:24Z",
            "AbuseEmail": "compliance@domain-inc.net",
            "Registrant": {
                "Name": "Domain Manager",
                "Organization": "Newfold Digital, Inc.",
                "Street": "5335 Gate Parkway",
                "City": "Jacksonville",
                "State": "FL",
                "PostalCode": "32256",
                "Country": "US",
                "Phone": "+1.9046806600",
                "Email": "corpdomains@newfold.com"
            },
            "Admin": {
                "Name": "REDACTED FOR PRIVACY",
                "Organization": "REDACTED FOR PRIVACY",
                "Street": "REDACTED FOR PRIVACY",
                "City": "REDACTED FOR PRIVACY",
                "State": "REDACTED FOR PRIVACY",
                "PostalCode": "REDACTED FOR PRIVACY",
                "Country": "REDACTED FOR PRIVACY",
                "Phone": "REDACTED FOR PRIVACY",
                "Fax": "REDACTED FOR PRIVACY",
                "Email": "REDACTED FOR PRIVACY"
            },
            "Tech": {
                "Name": "REDACTED FOR PRIVACY",
                "Organization": "REDACTED FOR PRIVACY",
                "Street": "REDACTED FOR PRIVACY",
                "City": "REDACTED FOR PRIVACY",
                "State": "REDACTED FOR PRIVACY",
                "PostalCode": "REDACTED FOR PRIVACY",
                "Country": "REDACTED FOR PRIVACY",
                "Phone": "REDACTED FOR PRIVACY",
                "Fax": "REDACTED FOR PRIVACY",
                "Email": "REDACTED FOR PRIVACY"
            },
            "NameServers": [
                "lee.ns.cloudflare.com",
                "sarah.ns.cloudflare.com"
            ],
            "Status": [
                "clientDeleteProhibited",
                "clientTransferProhibited",
                "clientUpdateProhibited"
            ],
            "DomainName": "domain.com",
            "RawText": "..."
        }
    }
}
```

#### Human Readable Output

>### ViewDNS WHOIS for domain.com
>
>|DomainName|RegistrarName|RegistrarIANAID|CreatedDate|UpdatedDate|ExpiresDate|AbuseEmail|Registrant|Admin|Tech|NameServers|Status|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| domain.com | Domain.com, LLC | 886 | 1994-07-01T04:00:00Z | 2024-01-22T21:36:01Z | 2031-01-07T13:34:24Z | compliance@domain-inc.net | Name: Domain Manager, Organization: Newfold Digital, Inc., Street: 5335 Gate Parkway, City: Jacksonville, State: FL, PostalCode: 32256, Country: US, Phone: +1.9046806600, Email: corpdomains@newfold.com | Name: REDACTED FOR PRIVACY, Organization: REDACTED FOR PRIVACY, Street: REDACTED FOR PRIVACY, City: REDACTED FOR PRIVACY, State: REDACTED FOR PRIVACY, PostalCode: REDACTED FOR PRIVACY, Country: REDACTED FOR PRIVACY, Phone: REDACTED FOR PRIVACY, Fax: REDACTED FOR PRIVACY, Email: REDACTED FOR PRIVACY | Name: REDACTED FOR PRIVACY, Organization: REDACTED FOR PRIVACY, Street: REDACTED FOR PRIVACY, City: REDACTED FOR PRIVACY, State: REDACTED FOR PRIVACY, PostalCode: REDACTED FOR PRIVACY, Country: REDACTED FOR PRIVACY, Phone: REDACTED FOR PRIVACY, Fax: REDACTED FOR PRIVACY, Email: REDACTED FOR PRIVACY | lee.ns.cloudflare.com,<br>sarah.ns.cloudflare.com | clientDeleteProhibited,<br>clientTransferProhibited,<br>clientUpdateProhibited |

### viewdns-reverse-ns

***
Finds the domains that use a given name server. Each call consumes one API query.

#### Base Command

`viewdns-reverse-ns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nameserver | The name server to search for, for example ns1.example.com. | Required |
| page | The page of API results to retrieve. Each page holds up to 10,000 results and each page retrieved consumes one API query. Default is 1. | Optional |
| limit | The maximum number of results to return from the retrieved page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.ReverseNS.Nameserver | String | The name server that was searched for. |
| ViewDNS.ReverseNS.DomainCount | Number | The total number of domains that use the name server. |
| ViewDNS.ReverseNS.TotalPages | Number | The total number of result pages available. |
| ViewDNS.ReverseNS.CurrentPage | Number | The result page that was retrieved. |
| ViewDNS.ReverseNS.Domains | String | The domains that use the name server. |

#### Command example

```!viewdns-reverse-ns nameserver=a.ns.facebook.com limit=3```

#### Context Example

```json
{
    "ViewDNS": {
        "ReverseNS": {
            "Nameserver": "a.ns.facebook.com",
            "DomainCount": 2217,
            "TotalPages": 1,
            "CurrentPage": 1,
            "Domains": [
                "123riff.com",
                "2cthefacebook.com",
                "zuckerberg.com"
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS Reverse NS for a.ns.facebook.com (showing 3 of 2217, page 1)
>
>|Domain|
>|---|
>| 123riff.com |
>| 2cthefacebook.com |
>| zuckerberg.com |

### viewdns-reverse-mx

***
Finds the domains that use a given mail server. Each call consumes one API query.

#### Base Command

`viewdns-reverse-mx`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mail_server | The mail server to search for, for example mail.example.com. | Required |
| page | The page of API results to retrieve. Each page holds up to 10,000 results and each page retrieved consumes one API query. Default is 1. | Optional |
| limit | The maximum number of results to return from the retrieved page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.ReverseMX.MailServer | String | The mail server that was searched for. |
| ViewDNS.ReverseMX.DomainCount | Number | The total number of domains that use the mail server. |
| ViewDNS.ReverseMX.TotalPages | Number | The total number of result pages available. |
| ViewDNS.ReverseMX.CurrentPage | Number | The result page that was retrieved. |
| ViewDNS.ReverseMX.Domains | String | The domains that use the mail server. |

#### Command example

```!viewdns-reverse-mx mail_server=mail.google.com limit=3```

#### Context Example

```json
{
    "ViewDNS": {
        "ReverseMX": {
            "MailServer": "mail.google.com",
            "DomainCount": 981,
            "TotalPages": 1,
            "CurrentPage": 1,
            "Domains": [
                "090803.com",
                "1sthealthcare.net",
                "academyhill.org"
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS Reverse MX for mail.google.com (showing 3 of 981, page 1)
>
>|Domain|
>|---|
>| 090803.com |
>| 1sthealthcare.net |
>| academyhill.org |

### viewdns-port-scan

***
Checks whether a set of common ports is open on a host. Each call consumes one API query. Use with care: this command makes ViewDNS servers actively connect to the target, which can be noticed by the target's owner.

#### Base Command

`viewdns-port-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The domain or public IP address to scan. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.PortScan.Host | String | The host that was scanned. |
| ViewDNS.PortScan.OpenPorts | Number | The numbers of the ports found open. |
| ViewDNS.PortScan.Ports.Number | Number | The port number. |
| ViewDNS.PortScan.Ports.Service | String | The service commonly run on the port. |
| ViewDNS.PortScan.Ports.Status | String | The status of the port \(open or closed\). |

#### Command example

```!viewdns-port-scan host=example.com```

#### Context Example

```json
{
    "ViewDNS": {
        "PortScan": {
            "Host": "example.com",
            "OpenPorts": [
                80,
                443
            ],
            "Ports": [
                {
                    "Number": 21,
                    "Service": "FTP",
                    "Status": "closed"
                },
                {
                    "Number": 22,
                    "Service": "SSH",
                    "Status": "closed"
                },
                {
                    "Number": 80,
                    "Service": "HTTP",
                    "Status": "open"
                },
                {
                    "Number": 443,
                    "Service": "HTTPS",
                    "Status": "open"
                },
                {
                    "Number": 3389,
                    "Service": "Remote Desktop",
                    "Status": "closed"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS Port Scan for example.com (2 open)
>
>|Number|Service|Status|
>|---|---|---|
>| 21 | FTP | closed |
>| 22 | SSH | closed |
>| 80 | HTTP | open |
>| 443 | HTTPS | open |
>| 3389 | Remote Desktop | closed |

### viewdns-ping

***
Measures latency and packet loss to a host from multiple locations around the world. Each call consumes one API query. Use with care: this command makes ViewDNS servers actively connect to the target, which can be noticed by the target's owner.

#### Base Command

`viewdns-ping`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The domain or public IP address to ping. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.Ping.Host | String | The host that was pinged. |
| ViewDNS.Ping.Results.Region | String | The region the ping was sent from. |
| ViewDNS.Ping.Results.Location | String | The city and country the ping was sent from. |
| ViewDNS.Ping.Results.IPAddress | String | The IP address the host resolved to at this location. |
| ViewDNS.Ping.Results.MinRTT | Number | The minimum round trip time, in milliseconds. |
| ViewDNS.Ping.Results.MaxRTT | Number | The maximum round trip time, in milliseconds. |
| ViewDNS.Ping.Results.AvgRTT | Number | The average round trip time, in milliseconds. |
| ViewDNS.Ping.Results.PacketLoss | String | The percentage of packets lost. |

#### Command example

```!viewdns-ping host=example.com```

#### Context Example

```json
{
    "ViewDNS": {
        "Ping": {
            "Host": "example.com",
            "Results": [
                {
                    "Region": "Asia",
                    "Location": "Hong Kong, China",
                    "IPAddress": "23.215.0.138",
                    "MinRTT": 207.854,
                    "MaxRTT": 208.289,
                    "AvgRTT": 208.123,
                    "PacketLoss": "25%"
                },
                {
                    "Region": "Asia",
                    "Location": "Mumbai, India",
                    "IPAddress": "96.7.128.198",
                    "MinRTT": 239.561,
                    "MaxRTT": 239.606,
                    "AvgRTT": 239.581,
                    "PacketLoss": "0%"
                },
                {
                    "Region": "South America",
                    "Location": "São Paulo, Brazil",
                    "IPAddress": "96.7.128.198",
                    "MinRTT": 176.05,
                    "MaxRTT": 176.093,
                    "AvgRTT": 176.061,
                    "PacketLoss": "0%"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS Ping for example.com (RTT in milliseconds)
>
>|Region|Location|IP Address|Min RTT|Avg RTT|Max RTT|Packet Loss|
>|---|---|---|---|---|---|---|
>| Asia | Hong Kong, China | 23.215.0.138 | 207.854 | 208.123 | 208.289 | 25% |
>| Asia | Mumbai, India | 96.7.128.198 | 239.561 | 239.581 | 239.606 | 0% |
>| South America | São Paulo, Brazil | 96.7.128.198 | 176.05 | 176.061 | 176.093 | 0% |

### viewdns-traceroute

***
Traces the network path from a ViewDNS server to a host. Each call consumes one API query. Use with care: this command makes ViewDNS servers actively connect to the target, which can be noticed by the target's owner.

#### Base Command

`viewdns-traceroute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The domain or IP address to trace the route to. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ViewDNS.Traceroute.Host | String | The host the route was traced to. |
| ViewDNS.Traceroute.Hops.Number | Number | The position of the hop in the route. |
| ViewDNS.Traceroute.Hops.Hostname | String | The hostname of the hop. |
| ViewDNS.Traceroute.Hops.IP | String | The IP address of the hop. |
| ViewDNS.Traceroute.Hops.RTT | Number | The round trip time to the hop, in milliseconds. |

#### Command example

```!viewdns-traceroute host=example.com```

#### Context Example

```json
{
    "ViewDNS": {
        "Traceroute": {
            "Host": "example.com",
            "Hops": [
                {
                    "Number": 1,
                    "Hostname": "obfuscated.internal.network.com",
                    "IP": "0.0.0.0",
                    "RTT": 0.0
                },
                {
                    "Number": 2,
                    "Hostname": "obfuscated.internal.network.com",
                    "IP": "0.0.0.0",
                    "RTT": 1.0
                },
                {
                    "Number": 3,
                    "Hostname": "air-mdsn-usshc.airstreamcomm.net",
                    "IP": "64.33.146.250",
                    "RTT": 3.513
                },
                {
                    "Number": 4,
                    "Hostname": "93.184.215.14",
                    "IP": "93.184.215.14",
                    "RTT": 7.156
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS Traceroute to example.com (RTT in milliseconds)
>
>|Number|Hostname|IP|RTT|
>|---|---|---|---|
>| 1 | obfuscated.internal.network.com | 0.0.0.0 | 0.0 |
>| 2 | obfuscated.internal.network.com | 0.0.0.0 | 1.0 |
>| 3 | air-mdsn-usshc.airstreamcomm.net | 64.33.146.250 | 3.513 |
>| 4 | 93.184.215.14 | 93.184.215.14 | 7.156 |

### domain

***
Enriches a domain with its WHOIS record and IP history. ViewDNS does not provide a verdict, so the DBot score is always 0 (Unknown). Runs only when reputation commands are enabled in the instance settings. Consumes two API queries per domain.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains to enrich. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| Domain.Name | String | The domain name. |
| Domain.Organization | String | The organization of the registrant. |
| Domain.CreationDate | Date | The date the domain was registered. |
| Domain.UpdatedDate | Date | The date the domain registration was last updated. |
| Domain.ExpirationDate | Date | The date the domain registration expires. |
| Domain.DomainStatus | String | The EPP status codes of the domain. |
| Domain.NameServers | String | The name servers of the domain. |
| Domain.Registrar.Name | String | The name of the registrar. |
| Domain.Registrar.AbuseEmail | String | The abuse contact email address of the registrar. |
| Domain.Registrant.Name | String | The name of the registrant. |
| Domain.Registrant.Email | String | The email address of the registrant. |
| Domain.Registrant.Phone | String | The phone number of the registrant. |
| Domain.Registrant.Country | String | The country of the registrant. |
| Domain.Admin.Name | String | The name of the administrative contact. |
| Domain.Admin.Email | String | The email address of the administrative contact. |
| Domain.Admin.Phone | String | The phone number of the administrative contact. |
| Domain.Admin.Country | String | The country of the administrative contact. |
| Domain.Tech.Name | String | The name of the technical contact. |
| Domain.Tech.Email | String | The email address of the technical contact. |
| Domain.Tech.Organization | String | The organization of the technical contact. |
| Domain.Tech.Country | String | The country of the technical contact. |
| Domain.WHOIS.CreationDate | Date | The date the domain was registered. |
| Domain.WHOIS.UpdatedDate | Date | The date the domain registration was last updated. |
| Domain.WHOIS.ExpirationDate | Date | The date the domain registration expires. |
| Domain.WHOIS.DomainStatus | String | The EPP status codes of the domain. |
| Domain.WHOIS.NameServers | String | The name servers of the domain. |
| Domain.WHOIS.Registrar.Name | String | The name of the registrar. |
| Domain.WHOIS.Registrar.AbuseEmail | String | The abuse contact email address of the registrar. |
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. |
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. |
| Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant. |
| Domain.WHOIS.Registrant.Country | String | The country of the registrant. |
| Domain.WHOIS.Admin.Name | String | The name of the administrative contact. |
| Domain.WHOIS.Admin.Email | String | The email address of the administrative contact. |
| Domain.WHOIS.Admin.Phone | String | The phone number of the administrative contact. |
| Domain.WHOIS.Admin.Country | String | The country of the administrative contact. |
| ViewDNS.Domain.Name | String | The domain name. |
| ViewDNS.Domain.Whois.DomainName | String | The domain name. |
| ViewDNS.Domain.Whois.RegistrarName | String | The name of the registrar. |
| ViewDNS.Domain.Whois.RegistrarIANAID | String | The IANA ID of the registrar. |
| ViewDNS.Domain.Whois.CreatedDate | Date | The date the domain was registered. |
| ViewDNS.Domain.Whois.UpdatedDate | Date | The date the domain registration was last updated. |
| ViewDNS.Domain.Whois.ExpiresDate | Date | The date the domain registration expires. |
| ViewDNS.Domain.Whois.AbuseEmail | String | The abuse contact email address. |
| ViewDNS.Domain.Whois.Registrant.Name | String | The name of the registrant. |
| ViewDNS.Domain.Whois.Registrant.Organization | String | The organization of the registrant. |
| ViewDNS.Domain.Whois.Registrant.Street | String | The street address of the registrant. |
| ViewDNS.Domain.Whois.Registrant.City | String | The city of the registrant. |
| ViewDNS.Domain.Whois.Registrant.State | String | The state or province of the registrant. |
| ViewDNS.Domain.Whois.Registrant.PostalCode | String | The postal code of the registrant. |
| ViewDNS.Domain.Whois.Registrant.Country | String | The country of the registrant. |
| ViewDNS.Domain.Whois.Registrant.Phone | String | The phone number of the registrant. |
| ViewDNS.Domain.Whois.Registrant.Fax | String | The fax number of the registrant. |
| ViewDNS.Domain.Whois.Registrant.Email | String | The email address of the registrant. |
| ViewDNS.Domain.Whois.Admin.Name | String | The name of the administrative contact. |
| ViewDNS.Domain.Whois.Admin.Organization | String | The organization of the administrative contact. |
| ViewDNS.Domain.Whois.Admin.Street | String | The street address of the administrative contact. |
| ViewDNS.Domain.Whois.Admin.City | String | The city of the administrative contact. |
| ViewDNS.Domain.Whois.Admin.State | String | The state or province of the administrative contact. |
| ViewDNS.Domain.Whois.Admin.PostalCode | String | The postal code of the administrative contact. |
| ViewDNS.Domain.Whois.Admin.Country | String | The country of the administrative contact. |
| ViewDNS.Domain.Whois.Admin.Phone | String | The phone number of the administrative contact. |
| ViewDNS.Domain.Whois.Admin.Fax | String | The fax number of the administrative contact. |
| ViewDNS.Domain.Whois.Admin.Email | String | The email address of the administrative contact. |
| ViewDNS.Domain.Whois.Tech.Name | String | The name of the technical contact. |
| ViewDNS.Domain.Whois.Tech.Organization | String | The organization of the technical contact. |
| ViewDNS.Domain.Whois.Tech.Street | String | The street address of the technical contact. |
| ViewDNS.Domain.Whois.Tech.City | String | The city of the technical contact. |
| ViewDNS.Domain.Whois.Tech.State | String | The state or province of the technical contact. |
| ViewDNS.Domain.Whois.Tech.PostalCode | String | The postal code of the technical contact. |
| ViewDNS.Domain.Whois.Tech.Country | String | The country of the technical contact. |
| ViewDNS.Domain.Whois.Tech.Phone | String | The phone number of the technical contact. |
| ViewDNS.Domain.Whois.Tech.Fax | String | The fax number of the technical contact. |
| ViewDNS.Domain.Whois.Tech.Email | String | The email address of the technical contact. |
| ViewDNS.Domain.Whois.NameServers | String | The name servers of the domain. |
| ViewDNS.Domain.Whois.Status | String | The EPP status codes of the domain. |
| ViewDNS.Domain.IPHistoryCount | Number | The total number of historical IP records available for the domain. |
| ViewDNS.Domain.IPHistory.IP | String | An IP address the domain was hosted on. |
| ViewDNS.Domain.IPHistory.Location | String | The location of the IP address. |
| ViewDNS.Domain.IPHistory.Owner | String | The owner of the IP address. |
| ViewDNS.Domain.IPHistory.LastSeen | Date | The date the domain was last seen on the IP address. |

#### Command example

```!domain domain=domain.com```

#### Context Example

```json
{
    "Domain": [
        {
            "Name": "domain.com",
            "Registrar": {
                "Name": "Domain.com, LLC",
                "AbuseEmail": "compliance@domain-inc.net",
                "AbusePhone": null
            },
            "Registrant": {
                "Name": "Domain Manager",
                "Email": "corpdomains@newfold.com",
                "Phone": "+1.9046806600",
                "Country": "US"
            },
            "Admin": {
                "Name": "REDACTED FOR PRIVACY",
                "Email": "REDACTED FOR PRIVACY",
                "Phone": "REDACTED FOR PRIVACY",
                "Country": "REDACTED FOR PRIVACY"
            },
            "Organization": "Newfold Digital, Inc.",
            "DomainStatus": [
                "clientDeleteProhibited",
                "clientTransferProhibited",
                "clientUpdateProhibited"
            ],
            "CreationDate": "1994-07-01T04:00:00Z",
            "UpdatedDate": "2024-01-22T21:36:01Z",
            "ExpirationDate": "2031-01-07T13:34:24Z",
            "NameServers": [
                "lee.ns.cloudflare.com",
                "sarah.ns.cloudflare.com"
            ],
            "Tech": {
                "Country": "REDACTED FOR PRIVACY",
                "Name": "REDACTED FOR PRIVACY",
                "Organization": "REDACTED FOR PRIVACY",
                "Email": "REDACTED FOR PRIVACY"
            },
            "WHOIS": {
                "Registrar": {
                    "Name": "Domain.com, LLC",
                    "AbuseEmail": "compliance@domain-inc.net",
                    "AbusePhone": null
                },
                "Registrant": {
                    "Name": "Domain Manager",
                    "Email": "corpdomains@newfold.com",
                    "Phone": "+1.9046806600",
                    "Country": "US"
                },
                "Admin": {
                    "Name": "REDACTED FOR PRIVACY",
                    "Email": "REDACTED FOR PRIVACY",
                    "Phone": "REDACTED FOR PRIVACY",
                    "Country": "REDACTED FOR PRIVACY"
                },
                "DomainStatus": [
                    "clientDeleteProhibited",
                    "clientTransferProhibited",
                    "clientUpdateProhibited"
                ],
                "CreationDate": "1994-07-01T04:00:00Z",
                "UpdatedDate": "2024-01-22T21:36:01Z",
                "ExpirationDate": "2031-01-07T13:34:24Z",
                "NameServers": [
                    "lee.ns.cloudflare.com",
                    "sarah.ns.cloudflare.com"
                ]
            }
        }
    ],
    "DBotScore": [
        {
            "Indicator": "domain.com",
            "Type": "domain",
            "Vendor": "ViewDNS",
            "Score": 0,
            "Reliability": "C - Fairly reliable"
        }
    ],
    "ViewDNS": {
        "Domain": {
            "Name": "domain.com",
            "Whois": {
                "RegistrarName": "Domain.com, LLC",
                "RegistrarIANAID": "886",
                "CreatedDate": "1994-07-01T04:00:00Z",
                "UpdatedDate": "2024-01-22T21:36:01Z",
                "ExpiresDate": "2031-01-07T13:34:24Z",
                "AbuseEmail": "compliance@domain-inc.net",
                "Registrant": {
                    "Name": "Domain Manager",
                    "Organization": "Newfold Digital, Inc.",
                    "Street": "5335 Gate Parkway",
                    "City": "Jacksonville",
                    "State": "FL",
                    "PostalCode": "32256",
                    "Country": "US",
                    "Phone": "+1.9046806600",
                    "Email": "corpdomains@newfold.com"
                },
                "Admin": {
                    "Name": "REDACTED FOR PRIVACY",
                    "Organization": "REDACTED FOR PRIVACY",
                    "Street": "REDACTED FOR PRIVACY",
                    "City": "REDACTED FOR PRIVACY",
                    "State": "REDACTED FOR PRIVACY",
                    "PostalCode": "REDACTED FOR PRIVACY",
                    "Country": "REDACTED FOR PRIVACY",
                    "Phone": "REDACTED FOR PRIVACY",
                    "Fax": "REDACTED FOR PRIVACY",
                    "Email": "REDACTED FOR PRIVACY"
                },
                "Tech": {
                    "Name": "REDACTED FOR PRIVACY",
                    "Organization": "REDACTED FOR PRIVACY",
                    "Street": "REDACTED FOR PRIVACY",
                    "City": "REDACTED FOR PRIVACY",
                    "State": "REDACTED FOR PRIVACY",
                    "PostalCode": "REDACTED FOR PRIVACY",
                    "Country": "REDACTED FOR PRIVACY",
                    "Phone": "REDACTED FOR PRIVACY",
                    "Fax": "REDACTED FOR PRIVACY",
                    "Email": "REDACTED FOR PRIVACY"
                },
                "NameServers": [
                    "lee.ns.cloudflare.com",
                    "sarah.ns.cloudflare.com"
                ],
                "Status": [
                    "clientDeleteProhibited",
                    "clientTransferProhibited",
                    "clientUpdateProhibited"
                ],
                "DomainName": "domain.com"
            },
            "IPHistoryCount": 4,
            "IPHistory": [
                {
                    "IP": "172.64.145.59",
                    "Location": "Unknown",
                    "Owner": "Cloudflare, Inc",
                    "LastSeen": "2024-09-20"
                },
                {
                    "IP": "104.18.42.197",
                    "Location": "Unknown",
                    "Owner": "Cloudflare, Inc",
                    "LastSeen": "2024-09-20"
                },
                {
                    "IP": "65.254.244.180",
                    "Location": "United States",
                    "Owner": "BIZLAND-SD",
                    "LastSeen": "2015-12-15"
                },
                {
                    "IP": "66.150.120.145",
                    "Location": "United States",
                    "Owner": "INTERNAP-BLK",
                    "LastSeen": "2012-06-03"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS WHOIS for domain.com
>
>|DomainName|RegistrarName|RegistrarIANAID|CreatedDate|UpdatedDate|ExpiresDate|AbuseEmail|Registrant|Admin|Tech|NameServers|Status|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| domain.com | Domain.com, LLC | 886 | 1994-07-01T04:00:00Z | 2024-01-22T21:36:01Z | 2031-01-07T13:34:24Z | compliance@domain-inc.net | Name: Domain Manager, Organization: Newfold Digital, Inc., Street: 5335 Gate Parkway, City: Jacksonville, State: FL, PostalCode: 32256, Country: US, Phone: +1.9046806600, Email: corpdomains@newfold.com | Name: REDACTED FOR PRIVACY, Organization: REDACTED FOR PRIVACY, Street: REDACTED FOR PRIVACY, City: REDACTED FOR PRIVACY, State: REDACTED FOR PRIVACY, PostalCode: REDACTED FOR PRIVACY, Country: REDACTED FOR PRIVACY, Phone: REDACTED FOR PRIVACY, Fax: REDACTED FOR PRIVACY, Email: REDACTED FOR PRIVACY | Name: REDACTED FOR PRIVACY, Organization: REDACTED FOR PRIVACY, Street: REDACTED FOR PRIVACY, City: REDACTED FOR PRIVACY, State: REDACTED FOR PRIVACY, PostalCode: REDACTED FOR PRIVACY, Country: REDACTED FOR PRIVACY, Phone: REDACTED FOR PRIVACY, Fax: REDACTED FOR PRIVACY, Email: REDACTED FOR PRIVACY | lee.ns.cloudflare.com,<br>sarah.ns.cloudflare.com | clientDeleteProhibited,<br>clientTransferProhibited,<br>clientUpdateProhibited |
>
>### ViewDNS IP History for domain.com (showing 4 of 4)
>
>|IP|Location|Owner|Last Seen|
>|---|---|---|---|
>| 172.64.145.59 | Unknown | Cloudflare, Inc | 2024-09-20 |
>| 104.18.42.197 | Unknown | Cloudflare, Inc | 2024-09-20 |
>| 65.254.244.180 | United States | BIZLAND-SD | 2015-12-15 |
>| 66.150.120.145 | United States | INTERNAP-BLK | 2012-06-03 |

### ip

***
Enriches an IP address with its WHOIS record and the domains hosted on it. ViewDNS does not provide a verdict, so the DBot score is always 0 (Unknown). Runs only when reputation commands are enabled in the instance settings. Consumes two API queries per IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to enrich. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| IP.Address | String | The IP address. |
| IP.ASN | String | The autonomous system number of the IP address. |
| IP.ASOwner | String | The owner of the network the IP address belongs to. |
| IP.Geo.Country | String | The country of the network the IP address belongs to. |
| IP.Organization.Name | String | The organization that owns the network. |
| IP.UpdatedDate | Date | The date the network registration was last updated. |
| IP.Registrar.Abuse.Name | String | The name of the abuse contact. |
| IP.Registrar.Abuse.Email | String | The email address of the abuse contact. |
| IP.Registrar.Abuse.Phone | String | The phone number of the abuse contact. |
| IP.Registrar.Abuse.Network | String | The network the abuse contact is responsible for. |
| ViewDNS.IP.Address | String | The IP address. |
| ViewDNS.IP.Whois.IP | String | The IP address. |
| ViewDNS.IP.Whois.Registry | String | The regional internet registry that holds the record. |
| ViewDNS.IP.Whois.Owner | String | The owner of the network. |
| ViewDNS.IP.Whois.NetName | String | The name of the network. |
| ViewDNS.IP.Whois.NetRange | String | The address range of the network. |
| ViewDNS.IP.Whois.CIDR | String | The network in CIDR notation. |
| ViewDNS.IP.Whois.ASN | String | The autonomous system number of the network, when available. |
| ViewDNS.IP.Whois.Country | String | The country of the network. |
| ViewDNS.IP.Whois.CreatedDate | Date | The date the network was registered. |
| ViewDNS.IP.Whois.UpdatedDate | Date | The date the network registration was last updated. |
| ViewDNS.IP.Whois.Abuse.Name | String | The name of the abuse contact. |
| ViewDNS.IP.Whois.Abuse.Organization | String | The organization of the abuse contact. |
| ViewDNS.IP.Whois.Abuse.Street | String | The street address of the abuse contact. |
| ViewDNS.IP.Whois.Abuse.City | String | The city of the abuse contact. |
| ViewDNS.IP.Whois.Abuse.State | String | The state or province of the abuse contact. |
| ViewDNS.IP.Whois.Abuse.PostalCode | String | The postal code of the abuse contact. |
| ViewDNS.IP.Whois.Abuse.Country | String | The country of the abuse contact. |
| ViewDNS.IP.Whois.Abuse.Phone | String | The phone number of the abuse contact. |
| ViewDNS.IP.Whois.Abuse.Fax | String | The fax number of the abuse contact. |
| ViewDNS.IP.Whois.Abuse.Email | String | The email address of the abuse contact. |
| ViewDNS.IP.Whois.Admin.Name | String | The name of the administrative contact. |
| ViewDNS.IP.Whois.Admin.Organization | String | The organization of the administrative contact. |
| ViewDNS.IP.Whois.Admin.Street | String | The street address of the administrative contact. |
| ViewDNS.IP.Whois.Admin.City | String | The city of the administrative contact. |
| ViewDNS.IP.Whois.Admin.State | String | The state or province of the administrative contact. |
| ViewDNS.IP.Whois.Admin.PostalCode | String | The postal code of the administrative contact. |
| ViewDNS.IP.Whois.Admin.Country | String | The country of the administrative contact. |
| ViewDNS.IP.Whois.Admin.Phone | String | The phone number of the administrative contact. |
| ViewDNS.IP.Whois.Admin.Fax | String | The fax number of the administrative contact. |
| ViewDNS.IP.Whois.Admin.Email | String | The email address of the administrative contact. |
| ViewDNS.IP.Whois.Tech.Name | String | The name of the technical contact. |
| ViewDNS.IP.Whois.Tech.Organization | String | The organization of the technical contact. |
| ViewDNS.IP.Whois.Tech.Street | String | The street address of the technical contact. |
| ViewDNS.IP.Whois.Tech.City | String | The city of the technical contact. |
| ViewDNS.IP.Whois.Tech.State | String | The state or province of the technical contact. |
| ViewDNS.IP.Whois.Tech.PostalCode | String | The postal code of the technical contact. |
| ViewDNS.IP.Whois.Tech.Country | String | The country of the technical contact. |
| ViewDNS.IP.Whois.Tech.Phone | String | The phone number of the technical contact. |
| ViewDNS.IP.Whois.Tech.Fax | String | The fax number of the technical contact. |
| ViewDNS.IP.Whois.Tech.Email | String | The email address of the technical contact. |
| ViewDNS.IP.Whois.Status | String | The status of the network registration. |
| ViewDNS.IP.HostedDomainCount | Number | The total number of domains hosted on the IP address. |
| ViewDNS.IP.HostedDomains.Name | String | A domain hosted on the IP address. |
| ViewDNS.IP.HostedDomains.LastResolved | Date | The date the domain was last seen resolving to the IP address. |

#### Command example

```!ip ip=8.8.8.8```

#### Context Example

```json
{
    "IP": [
        {
            "Address": "8.8.8.8",
            "ASOwner": "Google LLC (GOGL)",
            "UpdatedDate": "2023-12-28T00:00:00Z",
            "Registrar": {
                "Abuse": {
                    "Name": "Abuse",
                    "Network": "8.8.8.0/24",
                    "Phone": "+1-650-253-0000",
                    "Email": "network-abuse@google.com"
                }
            },
            "Geo": {
                "Country": "US"
            },
            "Organization": {
                "Name": "Google LLC (GOGL)"
            }
        }
    ],
    "DBotScore": [
        {
            "Indicator": "8.8.8.8",
            "Type": "ip",
            "Vendor": "ViewDNS",
            "Score": 0,
            "Reliability": "C - Fairly reliable"
        }
    ],
    "ViewDNS": {
        "IP": {
            "Address": "8.8.8.8",
            "Whois": {
                "Registry": "ARIN",
                "Owner": "Google LLC (GOGL)",
                "NetName": "GOGL",
                "NetRange": "8.8.8.0 - 8.8.8.255",
                "CIDR": "8.8.8.0/24",
                "Country": "US",
                "CreatedDate": "2023-12-28T00:00:00Z",
                "UpdatedDate": "2023-12-28T00:00:00Z",
                "Abuse": {
                    "Name": "Abuse",
                    "Phone": "+1-650-253-0000",
                    "Email": "network-abuse@google.com"
                },
                "Admin": {
                    "Street": "1600 Amphitheatre Parkway",
                    "City": "Mountain View",
                    "State": "CA",
                    "PostalCode": "94043",
                    "Fax": "US"
                },
                "Tech": {
                    "Name": "Google LLC",
                    "Phone": "+1-650-253-0000",
                    "Email": "arin-contact@google.com"
                },
                "IP": "8.8.8.8"
            },
            "HostedDomainCount": 5,
            "HostedDomains": [
                {
                    "Name": "atlabs.dev",
                    "LastResolved": "2024-09-28"
                },
                {
                    "Name": "example.com",
                    "LastResolved": "2024-10-02"
                },
                {
                    "Name": "example.edu",
                    "LastResolved": "2024-10-02"
                },
                {
                    "Name": "example.net",
                    "LastResolved": "2024-10-02"
                },
                {
                    "Name": "example.org",
                    "LastResolved": "2024-10-02"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ViewDNS WHOIS for 8.8.8.8
>
>|IP|Registry|Owner|NetName|NetRange|CIDR|Country|CreatedDate|UpdatedDate|Abuse|Admin|Tech|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8.8.8.8 | ARIN | Google LLC (GOGL) | GOGL | 8.8.8.0 - 8.8.8.255 | 8.8.8.0/24 | US | 2023-12-28T00:00:00Z | 2023-12-28T00:00:00Z | Name: Abuse, Phone: +1-650-253-0000, Email: network-abuse@google.com | Street: 1600 Amphitheatre Parkway, City: Mountain View, State: CA, PostalCode: 94043, Fax: US | Name: Google LLC, Phone: +1-650-253-0000, Email: arin-contact@google.com |
>
>### ViewDNS Domains Hosted on 8.8.8.8 (showing 5 of 5)
>
>|Name|Last Resolved|
>|---|---|
>| atlabs.dev | 2024-09-28 |
>| example.com | 2024-10-02 |
>| example.edu | 2024-10-02 |
>| example.net | 2024-10-02 |
>| example.org | 2024-10-02 |
