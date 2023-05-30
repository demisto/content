Provides data enrichment for domains.
This integration was integrated and tested with version 1.0 of Whois

## Configure Whois on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Whois.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Return Errors |  | False |
    | Proxy URL | Supports socks4/socks5/http connect proxies \(e.g. socks5h://host:1080\). Will effect all commands except for the \`ip\` command. | False |
    | Use system proxy settings | Effect the \`ip\` command and the other commands only if the Proxy URL is not set. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### whois
***
Provides data enrichment for domains.


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
| Domain.Name | string | The domain name. | 
| Domain.Whois.Name | string | The domain name. | 
| Domain.Whois.DomainStatus | string | The domain status. | 
| Domain.Whois.DNSSec | string | The domain name system security extension \(DNSSEC\). | 
| Domain.Whois.NameServers | string | The name servers. | 
| Domain.Whois.CreationDate | date | The date that the domain was created. | 
| Domain.Whois.UpdatedDate | date | The date that the domain was last updated. | 
| Domain.Whois.ExpirationDate | date | The date that the domain expires. | 
| Domain.Whois.Registrar.Name | string | The name of the registrar. | 
| Domain.Whois.Emails | string | The abuse emails. | 
| Domain.Whois.Registrar.AbuseEmail | string | The email address of the contact for reporting abuse. | 
| Domain.Whois.Registrant.name | string | The name of the registrant. | 
| Domain.Whois.Registrant.email | string | The email address of the registrant. | 
| Domain.Whois.Raw | string | The raw output. | 
| Domain.Whois.Administrator.country | string | The country of the domain administrator. | 
| Domain.Whois.Administrator.name | string | The name of domain administrator. | 
| Domain.Whois.Administrator.state | string | The state of domain administrator. | 
| Domain.Whois.Administrator.email | string | The email address of the domain administrator. | 
| Domain.Whois.Administrator.organization | string | The organization of the domain administrator. | 
| Domain.Whois.Administrator.postalcode | string | The postal code of the domain administrator | 
| Domain.Whois.Administrator.street | string | The street of the domain admin | 
| Domain.Whois.Administrator.phone | string | The phone number of the domain administrator. | 
| Domain.Whois.Administrator.city | string | The city of the domain administrator. | 
| Domain.Whois.TechAdmin.country | string | The country of tech administrator. | 
| Domain.Whois.TechAdmin.name | string | The name of tech administrator. | 
| Domain.Whois.TechAdmin.state | string | The state of tech administrator. | 
| Domain.Whois.TechAdmin.email | string | The email address of the tech administrator. | 
| Domain.Whois.TechAdmin.organization | string | The organization of the tech administrator. | 
| Domain.Whois.TechAdmin.postalcode | string | The postal code of the tech administrator. | 
| Domain.Whois.TechAdmin.street | string | The street of the tech administrator. | 
| Domain.Whois.TechAdmin.phone | string | The phone number of the tech administrator. | 
| Domain.Whois.TechAdmin.city | string | The city of the tech administrator. | 
| Domain.Whois.Registrant.country | string | The country of the registrant. | 
| Domain.Whois.Registrant.state | string | The state of the registrant. | 
| Domain.Whois.Registrant.organization | string | The organization of the registrant. | 
| Domain.Whois.Registrant.postalcode | string | The postal code of the registrant. | 
| Domain.Whois.Registrant.street | string | The street of the registrant. | 
| Domain.Whois.Registrant.phone | string | The phone number of the registrant. | 
| Domain.Whois.Registrant.city | string | The city of the registrant. | 
| Domain.Whois.ID | string | The ID of the domain. | 
| Domain.Whois.QueryStatus | string | The result of the command \("Success" or "Failed"\). | 
| Domain.Whois.QueryValue | string | The query requested by the user. | 
| Domain.Whois.QueryResult | Boolean | Whether the query found a matching result. | 

#### Command example
```!whois query=paloaltonetworks.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "paloaltonetworks.com",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "domain",
        "Vendor": "Whois"
    },
    "Domain": {
        "Admin": {
            "Country": "US",
            "Name": "Palo Alto Networks, Inc.",
            "State": "CA",
            "country": "US",
            "name": "Palo Alto Networks, Inc.",
            "state": "CA"
        },
        "CreationDate": "21-02-2005",
        "DomainStatus": [
            "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
            "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
            "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)"
        ],
        "ExpirationDate": "21-02-2024",
        "FeedRelatedIndicators": [
            {
                "type": "Email",
                "value": "abusecomplaints@markmonitor.com"
            },
            {
                "type": "Email",
                "value": "whoisrequest@markmonitor.com"
            }
        ],
        "Name": "paloaltonetworks.com",
        "NameServers": [
            "ns4.p23.dynect.net",
            "ns7.dnsmadeeasy.com",
            "ns2.p23.dynect.net",
            "ns3.p23.dynect.net",
            "ns1.p23.dynect.net",
            "ns5.dnsmadeeasy.com",
            "ns6.dnsmadeeasy.com"
        ],
        "Organization": "Palo Alto Networks, Inc.",
        "Registrant": {
            "Country": "US",
            "Organization": "Palo Alto Networks, Inc.",
            "State": "CA",
            "country": "US",
            "organization": "Palo Alto Networks, Inc.",
            "state": "CA"
        },
        "Registrar": {
            "Name": [
                "MarkMonitor, Inc."
            ]
        },
        "Tech": {
            "Country": "US",
            "Organization": "Palo Alto Networks, Inc."
        },
        "UpdatedDate": "11-08-2022",
        "WHOIS": {
            "Admin": {
                "country": "US",
                "name": "Palo Alto Networks, Inc.",
                "state": "CA"
            },
            "CreationDate": "21-02-2005",
            "DomainStatus": [
                "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
                "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
                "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)"
            ],
            "ExpirationDate": "21-02-2024",
            "NameServers": [
                "ns4.p23.dynect.net",
                "ns7.dnsmadeeasy.com",
                "ns2.p23.dynect.net",
                "ns3.p23.dynect.net",
                "ns1.p23.dynect.net",
                "ns5.dnsmadeeasy.com",
                "ns6.dnsmadeeasy.com"
            ],
            "Registrar": [
                "MarkMonitor, Inc."
            ],
            "UpdatedDate": "11-08-2022"
        },
        "Whois": {
            "Administrator": {
                "country": "US",
                "name": "Palo Alto Networks, Inc.",
                "state": "CA"
            },
            "CreationDate": "21-02-2005",
            "DomainStatus": [
                "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
                "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
                "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)"
            ],
            "Emails": [
                "abusecomplaints@markmonitor.com",
                "whoisrequest@markmonitor.com"
            ],
            "ExpirationDate": "21-02-2024",
            "ID": [
                "143300555_DOMAIN_COM-VRSN"
            ],
            "Name": "paloaltonetworks.com",
            "NameServers": [
                "ns4.p23.dynect.net",
                "ns7.dnsmadeeasy.com",
                "ns2.p23.dynect.net",
                "ns3.p23.dynect.net",
                "ns1.p23.dynect.net",
                "ns5.dnsmadeeasy.com",
                "ns6.dnsmadeeasy.com"
            ],
            "QueryResult": true,
            "QueryStatus": "Success",
            "QueryValue": "paloaltonetworks.com",
            "Raw": [
                "Domain Name: paloaltonetworks.com\nRegistry Domain ID: 143300555_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2022-08-11T11:55:26+0000\nCreation Date: 2005-02-21T02:42:10+0000\nRegistrar Registration Expiration Date: 2024-02-21T02:42:10+0000\nRegistrar: MarkMonitor, Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895770\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nRegistrant Organization: Palo Alto Networks, Inc.\nRegistrant State/Province: CA\nRegistrant Country: US\nRegistrant Email: Select Request Email Form at https://domains.markmonitor.com/whois/paloaltonetworks.com\nAdmin Organization: Palo Alto Networks, Inc.\nAdmin State/Province: CA\nAdmin Country: US\nAdmin Email: Select Request Email Form at https://domains.markmonitor.com/whois/paloaltonetworks.com\nTech Organization: Palo Alto Networks, Inc.\nTech State/Province: CA\nTech Country: US\nTech Email: Select Request Email Form at https://domains.markmonitor.com/whois/paloaltonetworks.com\nName Server: ns4.p23.dynect.net\nName Server: ns7.dnsmadeeasy.com\nName Server: ns2.p23.dynect.net\nName Server: ns3.p23.dynect.net\nName Server: ns1.p23.dynect.net\nName Server: ns5.dnsmadeeasy.com\nName Server: ns6.dnsmadeeasy.com\nDNSSEC: signedDelegation\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2022-08-22T16:18:20+0000 <<<\n\nFor more information on WHOIS status codes, please visit:\n  https://www.icann.org/resources/pages/epp-status-codes\n\nIf you wish to contact this domain\u2019s Registrant, Administrative, or Technical\ncontact, and such email address is not visible above, you may do so via our web\nform, pursuant to ICANN\u2019s Temporary Specification. To verify that you are not a\nrobot, please enter your email address to receive a link to a page that\nfacilitates email communication with the relevant contact(s).\n\nWeb-based WHOIS:\n  https://domains.markmonitor.com/whois\n\nIf you have a legitimate interest in viewing the non-public WHOIS details, send\nyour request and the reasons for your request to whoisrequest@markmonitor.com\nand specify the domain name in the subject line. We will review that request and\nmay ask for supporting documentation and explanation.\n\nThe data in MarkMonitor\u2019s WHOIS database is provided for information purposes,\nand to assist persons in obtaining information about or related to a domain\nname\u2019s registration record. While MarkMonitor believes the data to be accurate,\nthe data is provided \"as is\" with no guarantee or warranties regarding its\naccuracy.\n\nBy submitting a WHOIS query, you agree that you will use this data only for\nlawful purposes and that, under no circumstances will you use this data to:\n  (1) allow, enable, or otherwise support the transmission by email, telephone,\nor facsimile of mass, unsolicited, commercial advertising, or spam; or\n  (2) enable high volume, automated, or electronic processes that send queries,\ndata, or email to MarkMonitor (or its systems) or the domain name contacts (or\nits systems).\n\nMarkMonitor reserves the right to modify these terms at any time.\n\nBy submitting this query, you agree to abide by this policy.\n\nMarkMonitor Domain Management(TM)\nProtecting companies and consumers in a digital world.\n\nVisit MarkMonitor at https://www.markmonitor.com\nContact us at +1.8007459229\nIn Europe, at +44.02032062220\n--\n",
                "   Domain Name: PALOALTONETWORKS.COM\n   Registry Domain ID: 143300555_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.markmonitor.com\n   Registrar URL: http://www.markmonitor.com\n   Updated Date: 2022-08-11T11:55:26Z\n   Creation Date: 2005-02-21T02:42:10Z\n   Registry Expiry Date: 2024-02-21T02:42:10Z\n   Registrar: MarkMonitor Inc.\n   Registrar IANA ID: 292\n   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com\n   Registrar Abuse Contact Phone: +1.2086851750\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n   Name Server: NS1.P23.DYNECT.NET\n   Name Server: NS2.P23.DYNECT.NET\n   Name Server: NS3.P23.DYNECT.NET\n   Name Server: NS4.P23.DYNECT.NET\n   Name Server: NS5.DNSMADEEASY.COM\n   Name Server: NS6.DNSMADEEASY.COM\n   Name Server: NS7.DNSMADEEASY.COM\n   DNSSEC: signedDelegation\n   DNSSEC DS Data: 48100 8 1 090B3023BC51024B027B9CF45CADFBE78DF22C34\n   DNSSEC DS Data: 48100 8 2 99C5A51D59737F888F24F60E681E33B048F10BB212093EC24CB66D4CA7A71CE3\n   DNSSEC DS Data: 9113 13 2 181362F7FAF5EDBAAC773B0A9CA4B24E6B07408A9AAD5EA414CB84CB6BE3F1C8\n   DNSSEC DS Data: 49528 5 1 58E723E3E8E047E22C6EEA46E71203B96CEEDEA5\n   DNSSEC DS Data: 57256 5 2 9016B1C55520605BF76BA6C0612D9705CDA42D537085C5A93702A88BF4815C65\n   DNSSEC DS Data: 57256 5 1 CF097EE799C7A9542EDDE16367C3CC079BABB52E\n   DNSSEC DS Data: 49528 5 2 7077CA9EB6941F017FF162B030946028A4C3818D56BB15DD119DC9A0524BED46\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2022-08-22T16:27:47Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\n\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.\n"
            ],
            "Registrant": {
                "country": "US",
                "organization": "Palo Alto Networks, Inc.",
                "state": "CA"
            },
            "Registrar": {
                "Name": [
                    "MarkMonitor, Inc."
                ]
            },
            "TechAdmin": {
                "country": "US",
                "organization": "Palo Alto Networks, Inc.",
                "state": "CA"
            },
            "UpdatedDate": "11-08-2022"
        }
    }
}
```

#### Human Readable Output

>### Whois results for paloaltonetworks.com
>|Administrator|Creation Date|Domain Status|Emails|Expiration Date|ID|Name|NameServers|QueryStatus|Registrant|Registrar|Tech Admin|Updated Date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| name: Palo Alto Networks, Inc.<br/>state: CA<br/>country: US | 21-02-2005 | clientUpdateProhibited (https:<span>//</span>www.icann.org/epp#clientUpdateProhibited),<br/>clientTransferProhibited (https:<span>//</span>www.icann.org/epp#clientTransferProhibited),<br/>clientDeleteProhibited (https:<span>//</span>www.icann.org/epp#clientDeleteProhibited) | abusecomplaints@markmonitor.com,<br/>whoisrequest@markmonitor.com | 21-02-2024 | 143300555_DOMAIN_COM-VRSN | paloaltonetworks.com | ns4.p23.dynect.net,<br/>ns7.dnsmadeeasy.com,<br/>ns2.p23.dynect.net,<br/>ns3.p23.dynect.net,<br/>ns1.p23.dynect.net,<br/>ns5.dnsmadeeasy.com,<br/>ns6.dnsmadeeasy.com | Success | organization: Palo Alto Networks, Inc.<br/>state: CA<br/>country: US | MarkMonitor, Inc. | organization: Palo Alto Networks, Inc.<br/>state: CA<br/>country: US | 11-08-2022 |


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
| Domain.Name | string | The domain name. | 
| Domain.Whois.Name | string | The domain name. | 
| Domain.Whois.DomainStatus | string | The domain status. | 
| Domain.Whois.DNSSec | string | The domain name system security extension \(DNSSEC\). | 
| Domain.Whois.NameServers | string | The name servers. | 
| Domain.Whois.CreationDate | date | The date that the domain was created. | 
| Domain.Whois.UpdatedDate | date | The date that the domain was last updated. | 
| Domain.Whois.ExpirationDate | date | The date that the domain expires. | 
| Domain.Whois.Registrar.Name | string | The name of the registrar. | 
| Domain.Whois.Emails | string | The abuse emails. | 
| Domain.Whois.Registrar.AbuseEmail | string | The email address of the contact for reporting abuse. | 
| Domain.Whois.Registrant.name | string | The name of the registrant. | 
| Domain.Whois.Registrant.email | string | The email address of the registrant. | 
| Domain.Whois.Raw | string | The raw output. | 
| Domain.Whois.Administrator.country | string | The country of the domain administrator. | 
| Domain.Whois.Administrator.name | string | The name of domain administrator. | 
| Domain.Whois.Administrator.state | string | The state of domain administrator. | 
| Domain.Whois.Administrator.email | string | The email address of the domain administrator. | 
| Domain.Whois.Administrator.organization | string | The organization of the domain administrator. | 
| Domain.Whois.Administrator.postalcode | string | The postal code of the domain administrator | 
| Domain.Whois.Administrator.street | string | The street of the domain admin | 
| Domain.Whois.Administrator.phone | string | The phone number of the domain administrator. | 
| Domain.Whois.Administrator.city | string | The city of the domain administrator. | 
| Domain.Whois.TechAdmin.country | string | The country of tech administrator. | 
| Domain.Whois.TechAdmin.name | string | The name of tech administrator. | 
| Domain.Whois.TechAdmin.state | string | The state of tech administrator. | 
| Domain.Whois.TechAdmin.email | string | The email address of the tech administrator. | 
| Domain.Whois.TechAdmin.organization | string | The organization of the tech administrator. | 
| Domain.Whois.TechAdmin.postalcode | string | The postal code of the tech administrator. | 
| Domain.Whois.TechAdmin.street | string | The street of the tech administrator. | 
| Domain.Whois.TechAdmin.phone | string | The phone number of the tech administrator. | 
| Domain.Whois.TechAdmin.city | string | The city of the tech administrator. | 
| Domain.Whois.Registrant.country | string | The country of the registrant. | 
| Domain.Whois.Registrant.state | string | The state of the registrant. | 
| Domain.Whois.Registrant.organization | string | The organization of the registrant. | 
| Domain.Whois.Registrant.postalcode | string | The postal code of the registrant. | 
| Domain.Whois.Registrant.street | string | The street of the registrant. | 
| Domain.Whois.Registrant.phone | string | The phone number of the registrant. | 
| Domain.Whois.Registrant.city | string | The city of the registrant. | 
| Domain.Whois.ID | string | The ID of the domain. | 
| Domain.Whois.QueryStatus | string | The result of the command \("Success" or "Failed"\). | 
| Domain.Whois.QueryResult | Boolean | Whether the query found a matching result. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Name | String | The name of domain administrator. | 
| Domain.Admin.State | String | The state of domain administrator. | 
| Domain.Admin.country | String | The country of the domain administrator. | 
| Domain.Admin.name | String | The name of domain administrator. | 
| Domain.Admin.state | String | The state of domain administrator. | 
| Domain.CreationDate | Date | The date that the domain was created. | 
| Domain.DomainStatus | String | The domain status. | 
| Domain.ExpirationDate | Date | The date that the domain expires. | 
| Domain.FeedRelatedIndicators.type | String | Indicators that are associated with the Domain. | 
| Domain.FeedRelatedIndicators.value | String | The type of the indicators that are associated with the Domain. | 
| Domain.Name | String | The domain name. | 
| Domain.NameServers | String | The name servers. | 
| Domain.Organization | String | The organization name. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Registrant.Organization | String | The organization of the registrant. | 
| Domain.Registrant.State | String | The state of the registrant. | 
| Domain.Registrant.country | String | The country of the registrant. | 
| Domain.Registrant.organization | String | The organization of the registrant. | 
| Domain.Registrant.state | String | The state of the registrant. | 
| Domain.Registrar.Name | String | The name of the registrar. | 
| Domain.Tech.Country | String | The country of tech administrator. | 
| Domain.Tech.Organization | String | The organization of the tech administrator. | 
| Domain.UpdatedDate | Date | The date that the domain was last updated. | 

#### Command example
```!domain domain=google.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "google.com",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "domain",
        "Vendor": "Whois"
    },
    "Domain": {
        "Admin": {
            "Country": "US",
            "Name": "Google LLC",
            "State": "CA",
            "country": "US",
            "name": "Google LLC",
            "state": "CA"
        },
        "CreationDate": "15-09-1997",
        "DomainStatus": [
            "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
            "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
            "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
            "serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)",
            "serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)",
            "serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)"
        ],
        "ExpirationDate": "13-09-2028",
        "FeedRelatedIndicators": [
            {
                "type": "Email",
                "value": "abusecomplaints@markmonitor.com"
            },
            {
                "type": "Email",
                "value": "whoisrequest@markmonitor.com"
            }
        ],
        "Name": "google.com",
        "NameServers": [
            "ns2.google.com",
            "ns1.google.com",
            "ns4.google.com",
            "ns3.google.com"
        ],
        "Organization": "Google LLC",
        "Registrant": {
            "Country": "US",
            "Organization": "Google LLC",
            "State": "CA",
            "country": "US",
            "organization": "Google LLC",
            "state": "CA"
        },
        "Registrar": {
            "Name": [
                "MarkMonitor, Inc."
            ]
        },
        "Tech": {
            "Country": "US",
            "Organization": "Google LLC"
        },
        "UpdatedDate": "09-09-2019",
        "WHOIS": {
            "Admin": {
                "country": "US",
                "name": "Google LLC",
                "state": "CA"
            },
            "CreationDate": "15-09-1997",
            "DomainStatus": [
                "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
                "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
                "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
                "serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)",
                "serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)",
                "serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)"
            ],
            "ExpirationDate": "13-09-2028",
            "NameServers": [
                "ns2.google.com",
                "ns1.google.com",
                "ns4.google.com",
                "ns3.google.com"
            ],
            "Registrar": [
                "MarkMonitor, Inc."
            ],
            "UpdatedDate": "09-09-2019"
        },
        "Whois": {
            "Administrator": {
                "country": "US",
                "name": "Google LLC",
                "state": "CA"
            },
            "CreationDate": "15-09-1997",
            "DomainStatus": [
                "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
                "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
                "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
                "serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)",
                "serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)",
                "serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)"
            ],
            "Emails": [
                "abusecomplaints@markmonitor.com",
                "whoisrequest@markmonitor.com"
            ],
            "ExpirationDate": "13-09-2028",
            "ID": [
                "2138514_DOMAIN_COM-VRSN"
            ],
            "Name": "google.com",
            "NameServers": [
                "ns2.google.com",
                "ns1.google.com",
                "ns4.google.com",
                "ns3.google.com"
            ],
            "QueryResult": true,
            "QueryStatus": "Success",
            "QueryValue": null,
            "Raw": [
                "Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2019-09-09T15:39:04+0000\nCreation Date: 1997-09-15T07:00:00+0000\nRegistrar Registration Expiration Date: 2028-09-13T07:00:00+0000\nRegistrar: MarkMonitor, Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895770\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nRegistrant Organization: Google LLC\nRegistrant State/Province: CA\nRegistrant Country: US\nRegistrant Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com\nAdmin Organization: Google LLC\nAdmin State/Province: CA\nAdmin Country: US\nAdmin Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com\nTech Organization: Google LLC\nTech State/Province: CA\nTech Country: US\nTech Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com\nName Server: ns2.google.com\nName Server: ns1.google.com\nName Server: ns4.google.com\nName Server: ns3.google.com\nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2022-08-22T16:20:02+0000 <<<\n\nFor more information on WHOIS status codes, please visit:\n  https://www.icann.org/resources/pages/epp-status-codes\n\nIf you wish to contact this domain\u2019s Registrant, Administrative, or Technical\ncontact, and such email address is not visible above, you may do so via our web\nform, pursuant to ICANN\u2019s Temporary Specification. To verify that you are not a\nrobot, please enter your email address to receive a link to a page that\nfacilitates email communication with the relevant contact(s).\n\nWeb-based WHOIS:\n  https://domains.markmonitor.com/whois\n\nIf you have a legitimate interest in viewing the non-public WHOIS details, send\nyour request and the reasons for your request to whoisrequest@markmonitor.com\nand specify the domain name in the subject line. We will review that request and\nmay ask for supporting documentation and explanation.\n\nThe data in MarkMonitor\u2019s WHOIS database is provided for information purposes,\nand to assist persons in obtaining information about or related to a domain\nname\u2019s registration record. While MarkMonitor believes the data to be accurate,\nthe data is provided \"as is\" with no guarantee or warranties regarding its\naccuracy.\n\nBy submitting a WHOIS query, you agree that you will use this data only for\nlawful purposes and that, under no circumstances will you use this data to:\n  (1) allow, enable, or otherwise support the transmission by email, telephone,\nor facsimile of mass, unsolicited, commercial advertising, or spam; or\n  (2) enable high volume, automated, or electronic processes that send queries,\ndata, or email to MarkMonitor (or its systems) or the domain name contacts (or\nits systems).\n\nMarkMonitor reserves the right to modify these terms at any time.\n\nBy submitting this query, you agree to abide by this policy.\n\nMarkMonitor Domain Management(TM)\nProtecting companies and consumers in a digital world.\n\nVisit MarkMonitor at https://www.markmonitor.com\nContact us at +1.8007459229\nIn Europe, at +44.02032062220\n--\n",
                "   Domain Name: GOOGLE.COM\n   Registry Domain ID: 2138514_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.markmonitor.com\n   Registrar URL: http://www.markmonitor.com\n   Updated Date: 2019-09-09T15:39:04Z\n   Creation Date: 1997-09-15T04:00:00Z\n   Registry Expiry Date: 2028-09-14T04:00:00Z\n   Registrar: MarkMonitor Inc.\n   Registrar IANA ID: 292\n   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com\n   Registrar Abuse Contact Phone: +1.2086851750\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\n   Name Server: NS1.GOOGLE.COM\n   Name Server: NS2.GOOGLE.COM\n   Name Server: NS3.GOOGLE.COM\n   Name Server: NS4.GOOGLE.COM\n   DNSSEC: unsigned\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2022-08-22T16:27:47Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\n\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.\n"
            ],
            "Registrant": {
                "country": "US",
                "organization": "Google LLC",
                "state": "CA"
            },
            "Registrar": {
                "Name": [
                    "MarkMonitor, Inc."
                ]
            },
            "TechAdmin": {
                "country": "US",
                "organization": "Google LLC",
                "state": "CA"
            },
            "UpdatedDate": "09-09-2019"
        }
    }
}
```

#### Human Readable Output

>### Whois results for google.com
>|Administrator|Creation Date|Domain Status|Emails|Expiration Date|ID|Name|NameServers|QueryStatus|Registrant|Registrar|Tech Admin|Updated Date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| name: Google LLC<br/>state: CA<br/>country: US | 15-09-1997 | clientUpdateProhibited (https:<span>//</span>www.icann.org/epp#clientUpdateProhibited),<br/>clientTransferProhibited (https:<span>//</span>www.icann.org/epp#clientTransferProhibited),<br/>clientDeleteProhibited (https:<span>//</span>www.icann.org/epp#clientDeleteProhibited),<br/>serverUpdateProhibited (https:<span>//</span>www.icann.org/epp#serverUpdateProhibited),<br/>serverTransferProhibited (https:<span>//</span>www.icann.org/epp#serverTransferProhibited),<br/>serverDeleteProhibited (https:<span>//</span>www.icann.org/epp#serverDeleteProhibited) | abusecomplaints@markmonitor.com,<br/>whoisrequest@markmonitor.com | 13-09-2028 | 2138514_DOMAIN_COM-VRSN | google.com | ns2.google.com,<br/>ns1.google.com,<br/>ns4.google.com,<br/>ns3.google.com | Success | organization: Google LLC<br/>state: CA<br/>country: US | MarkMonitor, Inc. | organization: Google LLC<br/>state: CA<br/>country: US | 09-09-2019 |


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