CSCDomainManager uses rules-based technology, customizable reporting, granular user management, and more—and is the world's first multilingual domain management tool, available in English, French, and German.
This integration was integrated and tested with version 2.0.0 of CSCDomainManager.

## Configure CSCDomainManager in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | The endpoint URL | True |
| Token | The token to use for connection | True |
| API Key | The API Key to use for connection | True |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Access and Security
 Customers request access through their CSC service team.  Their service team will gather the details for
the service account that will be used to access the API; and
the API administrator(s) (one or more authorized client users) who will manage the credentials through our CSCDomainManagerSM web portal.
 
Please see attached API guide for reference.
 
CSC generates the API key and creates the service account, with requested permissions, that will be used to access the API.
 
The client API administrator then logs into our CSCDomainManagerSM at https://weblogin.cscglobal.com to retrieve the key and generate the bearer token for the API service account.

### Token Refresh
Token will expire after 30 consecutive days of no activity, you can reactive it by using the [token refresh endpoint](https://www.cscglobal.com/cscglobal/docs/dbs/domainmanager/api-v2/#/token/put_token_refresh).

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### csc-domains-search

***
Gets the domains by the applied filters

#### Base Command

`csc-domains-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | domain name to filter by, can start with like=, in=. | Optional | 
| registration_date | registration date to filter by, can start with gt=, ge=, lt=, le=. Date example 22-Apr-2024. | Optional | 
| email | email to filter by, can start with like=, in=. | Optional | 
| organization | organization to filter by, can start with like=, in=. | Optional | 
| registry_expiry_date | registry expiry date to filter by, can start with gt=, ge=, lt=, le=. Date example 22-Apr-2024. | Optional | 
| filter | can write your own filter according to selectors such as accountName, accountNumber, brandName, businessUnit, city, country, countryCode, criticalDomain, dnssecActivated, dnsType, domain, email, extension, fax, firstName, idnReferenceName, lastModifiedDate, lastModifiedDescription, lastModifiedReason, lastName, localAgent, managedStatus, nameServers, newGtld, organization, paidThroughDate, phone, phoneExtn, postalCode, qualifiedDomainName, redirectType, registrationDate, registryExpiryDate, serverDeleteProhibited, serverTransferProhibited, serverUpdateProhibited, stateProvince, street1, street2, urlForwarding, whoisPrivacy. | Optional | 
| sort | sorting the output by a selector and desc/asc, for example: propertyName,asc. | Optional | 
| page | page number. | Optional | 
| page_size | the size of rows in a page. | Optional | 
| limit | the limit of rows. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCDomainManager.Domain.qualifiedDomainName | String | the qualified domain name | 
| CSCDomainManager.Domain.domain | String | the domain | 
| CSCDomainManager.Domain.managedStatus | String | the managed status | 
| CSCDomainManager.Domain.registrationDate | String | the registration date | 
| CSCDomainManager.Domain.registryExpiryDate | String | the registry expiry date | 
| CSCDomainManager.Domain.paidThroughDate | String | paid through date | 
| CSCDomainManager.Domain.nameServers | String | servers names | 
| CSCDomainManager.Domain.dnsType | String | dns type | 
| CSCDomainManager.Domain.account.accountName | String | The name of the account associated with the domain. | 
| CSCDomainManager.Domain.account.accountNumber | String | The account number associated with the domain. | 
| CSCDomainManager.Domain.brandName | String | The brand name associated with the domain. | 
| CSCDomainManager.Domain.businessUnit | String | The business unit associated with the domain. | 
| CSCDomainManager.Domain.countryCode | String | The country code associated with the domain. | 
| CSCDomainManager.Domain.criticalDomain | Boolean | Indicates if the domain is critical. | 
| CSCDomainManager.Domain.customFields.name | String | The name of the custom field. | 
| CSCDomainManager.Domain.customFields.value | String | The value of the custom field. | 
| CSCDomainManager.Domain.dnssecActivated | String | Indicates if DNSSEC is activated for the domain. | 
| CSCDomainManager.Domain.extension | String | The extension of the domain, such as .com, .net, etc. | 
| CSCDomainManager.Domain.idn | String | Indicates if the domain is an Internationalized Domain Name \(IDN\). | 
| CSCDomainManager.Domain.idnReferenceName | String | The reference name for the IDN. | 
| CSCDomainManager.Domain.lastModifiedDate | Date | The date when the domain was last modified. | 
| CSCDomainManager.Domain.lastModifiedDescription | String | A description of the last modification made to the domain. | 
| CSCDomainManager.Domain.lastModifiedReason | String | The reason for the last modification made to the domain. | 
| CSCDomainManager.Domain.localAgent | Boolean | Indicates if the domain has a local agent. | 
| CSCDomainManager.Domain.newGtld | Boolean | Indicates if the domain is a new gTLD \(Generic Top-Level Domain\). | 
| CSCDomainManager.Domain.serverDeleteProhibited | Boolean | Indicates if the domain is prohibited from deletion by the server. | 
| CSCDomainManager.Domain.serverTransferProhibited | Boolean | Indicates if the domain is prohibited from transfer by the server. | 
| CSCDomainManager.Domain.serverUpdateProhibited | Boolean | Indicates if the domain is prohibited from updates by the server. | 
| CSCDomainManager.Domain.urlf.redirectType | String | The type of redirect used in URL forwarding for the domain. | 
| CSCDomainManager.Domain.urlf.urlForwarding | Boolean | Indicates if URL forwarding is enabled for the domain. | 
| CSCDomainManager.Domain.whoisContacts.city | String | The city of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.contactType | String | The type of WHOIS contact \(e.g., registrant, admin, tech\). | 
| CSCDomainManager.Domain.whoisContacts.country | String | The country of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.email | String | The email address of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.fax | String | The fax number of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.firstName | String | The first name of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.lastName | String | The last name of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.organization | String | The organization of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.phone | String | The phone number of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.phoneExtn | String | The phone extension of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.postalCode | String | The postal code of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.stateProvince | String | The state or province of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.street1 | String | The street address of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.street2 | String | The secondary street address of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisPrivacy | Boolean | Indicates if WHOIS privacy protection is enabled for the domain. | 

#### Command example
```!csc-domains-search domain_name=csc-panw.biz```
#### Context Example
```json
{
    "CSCDomainManager": {
        "Domain": {
            "account": {
                "accountName": "Palo Alto Networks - Integration",
                "accountNumber": "8601230"
            },
            "brandName": "",
            "businessUnit": "Cortex",
            "countryCode": "",
            "criticalDomain": false,
            "customFields": [
                {
                    "name": "Custom Field 2",
                    "value": "Custom-RefVal"
                },
                {
                    "name": "Department",
                    "value": "Xpanse"
                },
                {
                    "name": "PO Number",
                    "value": "2024-XR-586"
                }
            ],
            "dnsType": "CSC_BASIC",
            "dnssecActivated": "USAGE_UNKNOWN",
            "domain": "csc-panw",
            "extension": "biz",
            "idn": "",
            "idnReferenceName": "",
            "lastModifiedDate": "22-Apr-2024 UTC",
            "lastModifiedDescription": "Domain registered",
            "lastModifiedReason": "REGISTRATION_COMPLETE",
            "localAgent": false,
            "managedStatus": "ACTIVE",
            "nameServers": [
                "dns1.cscdns.net",
                "dns2.cscdns.net"
            ],
            "newGtld": false,
            "paidThroughDate": "22-Apr-2025 UTC",
            "qualifiedDomainName": "csc-panw.biz",
            "registrationDate": "22-Apr-2024 UTC",
            "registryExpiryDate": "22-Apr-2025 UTC",
            "serverDeleteProhibited": false,
            "serverTransferProhibited": false,
            "serverUpdateProhibited": false,
            "urlf": {
                "redirectType": "",
                "urlForwarding": false
            },
            "whoisContacts": [
                {
                    "city": "Wilmington",
                    "contactType": "REGISTRANT",
                    "country": "US",
                    "email": "admin@internationaladmin.com",
                    "fax": "",
                    "firstName": "Domain",
                    "lastName": "Administrator",
                    "organization": "CSC Corporate Domains, Inc.",
                    "phone": "+1.3026365400",
                    "phoneExtn": "",
                    "postalCode": "19808",
                    "stateProvince": "DE",
                    "street1": "251 Little Falls Drive",
                    "street2": ""
                },
                {
                    "city": "Wilmington",
                    "contactType": "ADMINISTRATIVE",
                    "country": "US",
                    "email": "admin@internationaladmin.com",
                    "fax": "",
                    "firstName": "Domain",
                    "lastName": "Administrator",
                    "organization": "CSC Corporate Domains, Inc.",
                    "phone": "+1.3026365400",
                    "phoneExtn": "",
                    "postalCode": "19808",
                    "stateProvince": "DE",
                    "street1": "251 Little Falls Drive",
                    "street2": ""
                },
                {
                    "city": "Wilmington",
                    "contactType": "TECHNICAL",
                    "country": "US",
                    "email": "dns-admin@cscglobal.com",
                    "fax": "",
                    "firstName": "DNS",
                    "lastName": "Administrator",
                    "organization": "CSC Corporate Domains, Inc.",
                    "phone": "+1.3026365400",
                    "phoneExtn": "",
                    "postalCode": "19808",
                    "stateProvince": "DE",
                    "street1": "251 Little Falls Drive",
                    "street2": ""
                }
            ],
            "whoisPrivacy": false
        }
    }
}
```

#### Human Readable Output

>### Filtered Domains
>|Qualified Domain Name|Domain|Managed Status|Registration Date|Registry Expiry Date|Paid Through Date|Name Servers|Dns Type|Whois Contact first Name|Whois Contact last Name|Whois Contact email|
>|---|---|---|---|---|---|---|---|---|---|---|
>| csc-panw.biz | csc-panw | ACTIVE | 22-Apr-2024 UTC | 22-Apr-2025 UTC | 22-Apr-2025 UTC | dns1.cscdns.net,<br/>dns2.cscdns.net | CSC_BASIC | Domain,<br/>Domain,<br/>DNS | Administrator,<br/>Administrator,<br/>Administrator | admin@internationaladmin.com,<br/>admin@internationaladmin.com,<br/>dns-admin@cscglobal.com |


### csc-domains-availability-check

***
Check registration availability for one or more domain names

#### Base Command

`csc-domains-availability-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | the domain name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCDomainManager.Domain.Availability.qualifiedDomainName | String | The fully qualified domain name \(FQDN\) being checked for availability. | 
| CSCDomainManager.Domain.Availability.result.code | String | The result code indicating the availability status of the domain. | 
| CSCDomainManager.Domain.Availability.result.message | String | A message providing additional information about the availability status. | 
| CSCDomainManager.Domain.Availability.basePrice.price | String | The base price for registering the domain. | 
| CSCDomainManager.Domain.Availability.basePrice.currency | String | The currency of the base price. | 
| CSCDomainManager.Domain.Availability.listOfTheTerms | String | A list of terms related to the availability of the domain. | 
| CSCDomainManager.Domain.Availability.availableTerms | Unknown | The terms available for the domain registration. | 

#### Command example
```!csc-domains-availability-check domain_name=csc-panw.biz```
#### Context Example
```json
{
    "CSCDomainManager": {
        "Domain": {
            "Availability": [
                {
                    "availableTerms": [],
                    "basePrice": {
                        "currency": "",
                        "price": null
                    },
                    "qualifiedDomainName": "csc-panw.biz",
                    "result": {
                        "code": "DOMAIN_IN_PORTFOLIO",
                        "message": "Domain already in portfolio"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Domains Availability
>|Qualified Domain Name|Code|Message|Price|Currency|List of the terms (months) available for registration|
>|---|---|---|---|---|---|
>| csc-panw.biz | DOMAIN_IN_PORTFOLIO | Domain already in portfolio |  |  |  |


### csc-domains-configuration-list

***
Get domains configuration information for owned domains with optional filtering

#### Base Command

`csc-domains-configuration-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | domain name to filter by, can start with like=, in=. | Optional | 
| registration_date | registration date to filter by, can start with gt=, ge=, lt=, le=. Date example 22-Apr-2024. | Optional | 
| domain_email | email to filter by, can start with like=, in=. | Optional | 
| filter | can write your own filter according to selectors such as accountName, accountNumber, brandName, businessUnit, city, country, countryCode, criticalDomain, dnssecActivated, dnsType, domain, email, extension, fax, firstName, idnReferenceName, lastModifiedDate, lastModifiedDescription, lastModifiedReason, lastName, localAgent, managedStatus, nameServers, newGtld, organization, paidThroughDate, phone, phoneExtn, postalCode, qualifiedDomainName, redirectType, registrationDate, registryExpiryDate, serverDeleteProhibited, serverTransferProhibited, serverUpdateProhibited, stateProvince, street1, street2, urlForwarding, whoisPrivacy. | Optional | 
| page | page number. | Optional | 
| page_size | the size of rows in a page. | Optional | 
| limit | to fill. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCDomainManager.Domain.Configuration.domain | String | the domain | 
| CSCDomainManager.Domain.Configuration.domainLabel | String | the domain label | 
| CSCDomainManager.Domain.Configuration.domainStatusCode | String | the domain status code | 
| CSCDomainManager.Domain.Configuration.domainExtension | String | extension | 
| CSCDomainManager.Domain.Configuration.country | String | country | 
| CSCDomainManager.Domain.Configuration.adminEmail | String | domain email | 
| CSCDomainManager.Domain.Configuration.adminName | String | admin name | 
| CSCDomainManager.Domain.Configuration.accountNumber | String | the account number | 
| CSCDomainManager.Domain.Configuration.accountName | String | the account name | 
| CSCDomainManager.Domain.Configuration.account.accountName | String | The name of the account associated with the domain. | 
| CSCDomainManager.Domain.Configuration.account.accountNumber | String | The account number associated with the domain. | 
| CSCDomainManager.Domain.Configuration.adminOrg | String | The administrative organization managing the domain. | 
| CSCDomainManager.Domain.Configuration.businessUnit | String | The business unit associated with the domain. | 
| CSCDomainManager.Domain.Configuration.dnsData.dnsDomain | String | The DNS domain information. | 
| CSCDomainManager.Domain.Configuration.dnsData.dnsProvider | String | The DNS provider for the domain. | 
| CSCDomainManager.Domain.Configuration.dnsHostingType | String | The type of DNS hosting used for the domain. | 
| CSCDomainManager.Domain.Configuration.dnsTraffic12moAve | Number | The average DNS traffic over the last 12 months. | 
| CSCDomainManager.Domain.Configuration.extension | String | The extension of the domain, such as .com, .net, etc. | 
| CSCDomainManager.Domain.Configuration.hasCscUrlf | Boolean | Indicates if the domain has CSC URL forwarding enabled. | 
| CSCDomainManager.Domain.Configuration.hasDkim | Boolean | Indicates if DKIM is configured for the domain. | 
| CSCDomainManager.Domain.Configuration.hasDmarc | Boolean | Indicates if DMARC is configured for the domain. | 
| CSCDomainManager.Domain.Configuration.hasDnssecDs | Boolean | Indicates if the domain has DNSSEC DS records. | 
| CSCDomainManager.Domain.Configuration.hasSpf | Boolean | Indicates if SPF is configured for the domain. | 
| CSCDomainManager.Domain.Configuration.hasWww | Boolean | Indicates if the domain has a WWW record. | 
| CSCDomainManager.Domain.Configuration.isGtld | Boolean | Indicates if the domain is a gTLD \(Generic Top-Level Domain\). | 
| CSCDomainManager.Domain.Configuration.isLive | Boolean | Indicates if the domain is live. | 
| CSCDomainManager.Domain.Configuration.isLiveType | String | The type of live status for the domain. | 
| CSCDomainManager.Domain.Configuration.isMultilockEligible | Boolean | Indicates if the domain is eligible for multilock. | 
| CSCDomainManager.Domain.Configuration.isVital | Boolean | Indicates if the domain is considered vital. | 
| CSCDomainManager.Domain.Configuration.multiLocked | Boolean | Indicates if the domain is multilocked. | 
| CSCDomainManager.Domain.Configuration.numLiveMx | Number | The number of live MX records for the domain. | 
| CSCDomainManager.Domain.Configuration.numRootA | Number | The number of root A records for the domain. | 
| CSCDomainManager.Domain.Configuration.numRootTxt | Number | The number of root TXT records for the domain. | 
| CSCDomainManager.Domain.Configuration.numSslNetcraft | Number | The number of SSL certificates detected by Netcraft for the domain. | 
| CSCDomainManager.Domain.Configuration.numWwwA | Number | The number of WWW A records for the domain. | 
| CSCDomainManager.Domain.Configuration.numWwwCname | Number | The number of WWW CNAME records for the domain. | 
| CSCDomainManager.Domain.Configuration.regEmail | String | The registration email address for the domain. | 
| CSCDomainManager.Domain.Configuration.regName | String | The registration name for the domain. | 
| CSCDomainManager.Domain.Configuration.regOrg | String | The registration organization for the domain. | 
| CSCDomainManager.Domain.Configuration.registryExpiryDate | Date | The expiration date of the domain registration in the registry. | 
| CSCDomainManager.Domain.Configuration.rootHttpCode | Number | The HTTP response code for the root domain. | 
| CSCDomainManager.Domain.Configuration.rootHttpUrl | Unknown | The HTTP URL for the root domain. | 
| CSCDomainManager.Domain.Configuration.rootIsUrlf | Boolean | Indicates if the root domain is URL forwarding enabled. | 
| CSCDomainManager.Domain.Configuration.serverDeleteProhibited | Unknown | Indicates if the domain is prohibited from deletion by the server. | 
| CSCDomainManager.Domain.Configuration.serverTransferProhibited | Unknown | Indicates if the domain is prohibited from transfer by the server. | 
| CSCDomainManager.Domain.Configuration.serverUpdateProhibited | Unknown | Indicates if the domain is prohibited from updates by the server. | 
| CSCDomainManager.Domain.Configuration.techEmail | String | The technical contact email address for the domain. | 
| CSCDomainManager.Domain.Configuration.techName | String | The technical contact name for the domain. | 
| CSCDomainManager.Domain.Configuration.techOrg | String | The technical contact organization for the domain. | 
| CSCDomainManager.Domain.Configuration.tld | String | The top-level domain \(TLD\) of the domain. | 
| CSCDomainManager.Domain.Configuration.urlfTraffic12moAve | Number | The average URL forwarding traffic over the last 12 months. | 
| CSCDomainManager.Domain.Configuration.valueRootA | Unknown | The value of root A records for the domain. | 
| CSCDomainManager.Domain.Configuration.valueRootMx | Unknown | The value of root MX records for the domain. | 
| CSCDomainManager.Domain.Configuration.valueRootTxt | Unknown | The value of root TXT records for the domain. | 
| CSCDomainManager.Domain.Configuration.valueWwwA | Unknown | The value of WWW A records for the domain. | 
| CSCDomainManager.Domain.Configuration.valueWwwCname | Unknown | The value of WWW CNAME records for the domain. | 
| CSCDomainManager.Domain.Configuration.wwwHttpCode | Number | The HTTP response code for the WWW domain. | 
| CSCDomainManager.Domain.Configuration.wwwHttpUrl | Unknown | The HTTP URL for the WWW domain. | 
| CSCDomainManager.Domain.Configuration.wwwIsUrlf | Boolean | Indicates if the WWW domain is URL forwarding enabled. | 

#### Command example
```!csc-domains-configuration-list domain_name=csc-panw.biz```
#### Context Example
```json
{
    "CSCDomainManager": {
        "Domain": {
            "Configuration": {
                "account": {
                    "accountName": "Palo Alto Networks - Integration",
                    "accountNumber": "8601230"
                },
                "adminEmail": "admin@internationaladmin.com",
                "adminName": "Domain Administrator",
                "adminOrg": "CSC Corporate Domains, Inc.",
                "businessUnit": "Cortex",
                "country": "GTLD",
                "dnsData": [
                    {
                        "dnsDomain": "ns1.1-877namebid.com",
                        "dnsProvider": "1-877NameBid.com LLC, (United States)"
                    },
                    {
                        "dnsDomain": "ns2.1-877namebid.com",
                        "dnsProvider": "1-877NameBid.com LLC, (United States)"
                    }
                ],
                "dnsHostingType": "THIRDPARTY",
                "dnsTraffic12moAve": 790,
                "domain": "csc-panw.biz",
                "domainLabel": "csc-panw",
                "domainStatusCode": "ACT",
                "extension": "biz",
                "hasCscUrlf": false,
                "hasDkim": false,
                "hasDmarc": false,
                "hasDnssecDs": false,
                "hasSpf": false,
                "hasWww": false,
                "isGtld": false,
                "isLive": false,
                "isLiveType": "Not Live",
                "isMultilockEligible": true,
                "isVital": false,
                "multiLocked": false,
                "numLiveMx": 0,
                "numRootA": 0,
                "numRootTxt": 0,
                "numSslNetcraft": 0,
                "numWwwA": 0,
                "numWwwCname": 0,
                "regEmail": "admin@internationaladmin.com",
                "regName": "Domain Administrator",
                "regOrg": "CSC Corporate Domains, Inc.",
                "registryExpiryDate": "2025-04-22",
                "rootHttpCode": 0,
                "rootHttpUrl": null,
                "rootIsUrlf": false,
                "serverDeleteProhibited": null,
                "serverTransferProhibited": null,
                "serverUpdateProhibited": null,
                "techEmail": "dns-admin@cscglobal.com",
                "techName": "Domain Administrator",
                "techOrg": "CSC Corporate Domains, Inc.",
                "tld": "biz",
                "urlfTraffic12moAve": 0,
                "valueRootA": null,
                "valueRootMx": null,
                "valueRootTxt": null,
                "valueWwwA": null,
                "valueWwwCname": null,
                "wwwHttpCode": 0,
                "wwwHttpUrl": null,
                "wwwIsUrlf": true
            }
        }
    }
}
```

#### Human Readable Output

>### Filtered Configurations
>|Domain|Domain Label|Domain Status Code|Domain extension|Country|Admin Email|Admin Name|Account Number|Account Name|
>|---|---|---|---|---|---|---|---|---|
>| csc-panw.biz | csc-panw | ACT | biz | GTLD | admin@internationaladmin.com | admin@internationaladmin.com | 8601230 | Palo Alto Networks - Integration |


### domain

***
Get domain data by qualified domain name

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Will contain domains values. Example: If you need to get the object_ids of indicator example.com then the value will be example.com. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.CreationDate | String | Creation dare | 
| Domain.DomainIDNName | String | Domain ID name | 
| Domain.ExpirationDate | String | Expiration date | 
| DomainUpdatedDate | String | Updated date | 
| Domain.NameServers | String | Servers Name | 
| Domain.Registrant.Name | String | Registrant name | 
| Domain.Registrant.Email | String | Registrant email | 
| Domain.Registrant.Phone | String | Registrant phone | 
| Domain.Registrant.Country | String | Registrant country | 
| Domain.Admin.Name | String | Admin name | 
| Domain.Admin.Email | String | Admin email | 
| Domain.Admin.Phone | String | Admin phone | 
| Domain.Admin.Country | String | Admin country | 
| Domain.Tech.Country | String | Tech country | 
| Domain.Tech.Name | String | Tech name | 
| Domain.Tech.Organization | String | Tech organization | 
| Domain.Tech.Email | String | Tech email | 
| CSCDomainManager.Domain.account.accountName | String | Domain account name | 
| CSCDomainManager.Domain.account.accountNumber | String | Domain account number | 
| CSCDomainManager.Domain.brandName | String | Domain brand name | 
| CSCDomainManager.Domain.businessUnit | String | Domain business unit | 
| CSCDomainManager.Domain.countryCode | String | Domain country code | 
| CSCDomainManager.Domain.criticalDomain | Boolean | Domain critical domain | 
| CSCDomainManager.Domain.customFields.name | String | Domain custom fields name | 
| CSCDomainManager.Domain.customFields.value | String | The value of custom fields associated with the domain. | 
| CSCDomainManager.Domain.dnsType | String | The type of DNS used by the domain. | 
| CSCDomainManager.Domain.dnssecActivated | String | Indicates whether DNSSEC is activated for the domain. | 
| CSCDomainManager.Domain.domain | String | The domain name. | 
| CSCDomainManager.Domain.extension | String | The extension of the domain, such as .com, .net, etc. | 
| CSCDomainManager.Domain.idn | String | Indicates if the domain is an Internationalized Domain Name \(IDN\). | 
| CSCDomainManager.Domain.idnReferenceName | String | The reference name for the Internationalized Domain Name \(IDN\). | 
| CSCDomainManager.Domain.lastModifiedDate | Date | The date when the domain was last modified. | 
| CSCDomainManager.Domain.lastModifiedDescription | String | A description of the last modification made to the domain. | 
| CSCDomainManager.Domain.lastModifiedReason | String | The reason for the last modification of the domain. | 
| CSCDomainManager.Domain.localAgent | Boolean | Indicates if a local agent is associated with the domain. | 
| CSCDomainManager.Domain.managedStatus | String | The managed status of the domain. | 
| CSCDomainManager.Domain.nameServers | String | The name servers associated with the domain. | 
| CSCDomainManager.Domain.newGtld | Boolean | Indicates if the domain is a new gTLD \(Generic Top-Level Domain\). | 
| CSCDomainManager.Domain.paidThroughDate | Date | The date through which the domain has been paid. | 
| CSCDomainManager.Domain.qualifiedDomainName | String | The fully qualified domain name \(FQDN\). | 
| CSCDomainManager.Domain.registrationDate | Date | The date when the domain was registered. | 
| CSCDomainManager.Domain.registryExpiryDate | Date | The expiration date of the domain registration in the registry. | 
| CSCDomainManager.Domain.serverDeleteProhibited | Boolean | Indicates if the domain is prohibited from deletion by the server. | 
| CSCDomainManager.Domain.serverTransferProhibited | Boolean | Indicates if the domain is prohibited from transfer by the server. | 
| CSCDomainManager.Domain.serverUpdateProhibited | Boolean | Indicates if the domain is prohibited from updates by the server. | 
| CSCDomainManager.Domain.urlf.redirectType | String | The type of URL forwarding redirect. | 
| CSCDomainManager.Domain.urlf.urlForwarding | Boolean | Indicates if URL forwarding is enabled for the domain. | 
| CSCDomainManager.Domain.whoisContacts.city | String | The city of the WHOIS contact. | 
| CSCDomainManager.Domain.whoisContacts.contactType | String | The type of WHOIS contact \(e.g., Registrant, Admin, Tech\). | 
| Domain.WHOIS.Admin.Country | String | The country of the admin contact in the WHOIS record. | 
| Domain.WHOIS.Admin.Email | String | The email of the admin contact in the WHOIS record. | 
| Domain.WHOIS.Admin.Name | String | The name of the admin contact in the WHOIS record. | 
| Domain.WHOIS.Admin.Phone | String | The phone number of the admin contact in the WHOIS record. | 
| Domain.WHOIS.CreationDate | Date | The creation date of the domain in the WHOIS record. | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain in the WHOIS record. | 
| Domain.WHOIS.NameServers | String | The name servers listed in the WHOIS record. | 
| Domain.WHOIS.Registrant.Country | String | The country of the registrant in the WHOIS record. | 
| Domain.WHOIS.Registrant.Email | String | The email of the registrant in the WHOIS record. | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant in the WHOIS record. | 
| Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant in the WHOIS record. | 

#### Command example
```!domain domain=csc-panw.biz```
#### Context Example
```json
{
    "CSCDomainManager": {
        "Domain": {
            "account": {
                "accountName": "Palo Alto Networks - Integration",
                "accountNumber": "8601230"
            },
            "brandName": "",
            "businessUnit": "Cortex",
            "countryCode": "",
            "criticalDomain": false,
            "customFields": [
                {
                    "name": "Custom Field 2",
                    "value": "Custom-RefVal"
                },
                {
                    "name": "Department",
                    "value": "Xpanse"
                },
                {
                    "name": "PO Number",
                    "value": "2024-XR-586"
                }
            ],
            "dnsType": "CSC_BASIC",
            "dnssecActivated": "USAGE_UNKNOWN",
            "domain": "csc-panw",
            "extension": "biz",
            "idn": "",
            "idnReferenceName": "",
            "lastModifiedDate": "22-Apr-2024 UTC",
            "lastModifiedDescription": "Domain registered",
            "lastModifiedReason": "REGISTRATION_COMPLETE",
            "localAgent": false,
            "managedStatus": "ACTIVE",
            "nameServers": [
                "dns1.cscdns.net",
                "dns2.cscdns.net"
            ],
            "newGtld": false,
            "paidThroughDate": "22-Apr-2025 UTC",
            "qualifiedDomainName": "csc-panw.biz",
            "registrationDate": "22-Apr-2024 UTC",
            "registryExpiryDate": "22-Apr-2025 UTC",
            "serverDeleteProhibited": false,
            "serverTransferProhibited": false,
            "serverUpdateProhibited": false,
            "urlf": {
                "redirectType": "",
                "urlForwarding": false
            },
            "whoisContacts": [
                {
                    "city": "Wilmington",
                    "contactType": "REGISTRANT",
                    "country": "US",
                    "email": "admin@internationaladmin.com",
                    "fax": "",
                    "firstName": "Domain",
                    "lastName": "Administrator",
                    "organization": "CSC Corporate Domains, Inc.",
                    "phone": "+1.3026365400",
                    "phoneExtn": "",
                    "postalCode": "19808",
                    "stateProvince": "DE",
                    "street1": "251 Little Falls Drive",
                    "street2": ""
                },
                {
                    "city": "Wilmington",
                    "contactType": "ADMINISTRATIVE",
                    "country": "US",
                    "email": "admin@internationaladmin.com",
                    "fax": "",
                    "firstName": "Domain",
                    "lastName": "Administrator",
                    "organization": "CSC Corporate Domains, Inc.",
                    "phone": "+1.3026365400",
                    "phoneExtn": "",
                    "postalCode": "19808",
                    "stateProvince": "DE",
                    "street1": "251 Little Falls Drive",
                    "street2": ""
                },
                {
                    "city": "Wilmington",
                    "contactType": "TECHNICAL",
                    "country": "US",
                    "email": "dns-admin@cscglobal.com",
                    "fax": "",
                    "firstName": "DNS",
                    "lastName": "Administrator",
                    "organization": "CSC Corporate Domains, Inc.",
                    "phone": "+1.3026365400",
                    "phoneExtn": "",
                    "postalCode": "19808",
                    "stateProvince": "DE",
                    "street1": "251 Little Falls Drive",
                    "street2": ""
                }
            ],
            "whoisPrivacy": false
        }
    },
    "DBotScore": {
        "Indicator": "csc-panw.biz",
        "Reliability": "A - Completely reliable",
        "Score": 0,
        "Type": "domain",
        "Vendor": "CSCDomainManager"
    },
    "Domain": {
        "Admin": {
            "Country": [
                "US"
            ],
            "Email": [
                "admin@internationaladmin.com"
            ],
            "Name": [
                "Domain Administrator"
            ],
            "Phone": [
                "+1.3026365400"
            ]
        },
        "CreationDate": "22-Apr-2024 UTC",
        "ExpirationDate": "22-Apr-2025 UTC",
        "Name": "csc-panw",
        "NameServers": [
            "dns1.cscdns.net",
            "dns2.cscdns.net"
        ],
        "Registrant": {
            "Country": [
                "US"
            ],
            "Email": [
                "admin@internationaladmin.com"
            ],
            "Name": [
                "Domain Administrator"
            ],
            "Phone": [
                "+1.3026365400"
            ]
        },
        "Tech": {
            "Country": [
                "US"
            ],
            "Email": [
                "dns-admin@cscglobal.com"
            ],
            "Name": [
                "DNS Administrator"
            ],
            "Organization": [
                "CSC Corporate Domains, Inc."
            ]
        },
        "WHOIS": {
            "Admin": {
                "Country": [
                    "US"
                ],
                "Email": [
                    "admin@internationaladmin.com"
                ],
                "Name": [
                    "Domain Administrator"
                ],
                "Phone": [
                    "+1.3026365400"
                ]
            },
            "CreationDate": "22-Apr-2024 UTC",
            "ExpirationDate": "22-Apr-2025 UTC",
            "NameServers": [
                "dns1.cscdns.net",
                "dns2.cscdns.net"
            ],
            "Registrant": {
                "Country": [
                    "US"
                ],
                "Email": [
                    "admin@internationaladmin.com"
                ],
                "Name": [
                    "Domain Administrator"
                ],
                "Phone": [
                    "+1.3026365400"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Domain
>|Qualified Domain Name|Domain|Idn|Generic top-level domains|Managed Status|Registration Date|Registry Expiry Date|Paid Through Date|Country Code|Server Delete Prohibited|Server Transfer Prohibited|Server Update Prohibited|Name Servers|Dns Type|Whois Contact first Name|Whois Contact last Name|Whois Contact email|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| csc-panw.biz | csc-panw |  | false | ACTIVE | 22-Apr-2024 UTC | 22-Apr-2025 UTC | 22-Apr-2025 UTC |  |  | false |  | dns1.cscdns.net,<br/>dns2.cscdns.net | CSC_BASIC | Domain | Administrator | admin@internationaladmin.com |


### csc-domains-configuration-search

***
Get configuration information for owned domains with optional filtering.

#### Base Command

`csc-domains-configuration-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | Domain name to filter by. Can start with like=, in=. | Optional | 
| registration_date | Registration date to filter by. Can start with gt=, ge=, lt=, le=. Date example: 22-Apr-2024, 22/4/24, 22-4-24. | Optional | 
| domain_email | Email to filter by. Can start with like=, in=. | Optional | 
| filter | Create a filter using selectors such as: accountName, accountNumber, brandName, businessUnit, city, country, countryCode, criticalDomain, dnssecActivated, dnsType, domain, email, extension, fax, firstName, idnReferenceName, lastModifiedDate, lastModifiedDescription, lastModifiedReason, lastName, localAgent, managedStatus, nameServers, newGtld, organization, paidThroughDate, phone, phoneExtn, postalCode, qualifiedDomainName, redirectType, registrationDate, registryExpiryDate, serverDeleteProhibited, serverTransferProhibited, serverUpdateProhibited, stateProvince, street1, street2, urlForwarding, whoisPrivacy. For example: filter=lastName==Administrator. | Optional | 
| page | Page number. | Optional | 
| page_size | The number of rows in a page. | Optional | 
| limit | The maximum number of rows to present. | Optional | 

#### Context Output

| **Path** | **Type** | **Description**   |
| --- | --- |-------------------|
| CSCDomainManager.Domain.Configuration.domain | String | The domain. |
| CSCDomainManager.Domain.Configuration.domainLabel | String | The domain label. |
| CSCDomainManager.Domain.Configuration.domainStatusCode | String | The domain status code. |
| CSCDomainManager.Domain.Configuration.domainExtension | String | The domain extension. |
| CSCDomainManager.Domain.Configuration.country | String | Country associated with the domain. |
| CSCDomainManager.Domain.Configuration.adminEmail | String | Domain email. |
| CSCDomainManager.Domain.Configuration.adminName | String | Admin name associated with the domain. |
| CSCDomainManager.Domain.Configuration.accountNumber | String | The account number associated with the domain. |
| CSCDomainManager.Domain.Configuration.accountName | String | The account name associated with the domain. |
| CSCDomainManager.Domain.Configuration.account.accountName | String | The name of the account associated with the domain. |
| CSCDomainManager.Domain.Configuration.account.accountNumber | String | The account number associated with the domain. |
| CSCDomainManager.Domain.Configuration.adminOrg | String | The administrative organization managing the domain. |
| CSCDomainManager.Domain.Configuration.businessUnit | String | The business unit associated with the domain. |
| CSCDomainManager.Domain.Configuration.dnsData.dnsDomain | String | The DNS domain information. |
| CSCDomainManager.Domain.Configuration.dnsData.dnsProvider | String | The DNS provider for the domain. |
| CSCDomainManager.Domain.Configuration.dnsHostingType | String | The type of DNS hosting used for the domain. |
| CSCDomainManager.Domain.Configuration.dnsTraffic12moAve | Number | The average DNS traffic over the last 12 months. |
| CSCDomainManager.Domain.Configuration.extension | String | The extension of the domain, such as .com, .net, etc. |
| CSCDomainManager.Domain.Configuration.hasCscUrlf | Boolean | Indicates if the domain has CSC URL forwarding enabled. |
| CSCDomainManager.Domain.Configuration.hasDkim | Boolean | Indicates if DKIM is configured for the domain. |
| CSCDomainManager.Domain.Configuration.hasDmarc | Boolean | Indicates if DMARC is configured for the domain. |
| CSCDomainManager.Domain.Configuration.hasDnssecDs | Boolean | Indicates if the domain has DNSSEC DS records. |
| CSCDomainManager.Domain.Configuration.hasSpf | Boolean | Indicates if SPF is configured for the domain. |
| CSCDomainManager.Domain.Configuration.hasWww | Boolean | Indicates if the domain has a WWW record. |
| CSCDomainManager.Domain.Configuration.isGtld | Boolean | Indicates if the domain is a gTLD (Generic Top-Level Domain). |
| CSCDomainManager.Domain.Configuration.isLive | Boolean | Indicates if the domain is live. |
| CSCDomainManager.Domain.Configuration.isLiveType | String | The type of live status for the domain. |
| CSCDomainManager.Domain.Configuration.isMultilockEligible | Boolean | Indicates if the domain is eligible for multilock. |
| CSCDomainManager.Domain.Configuration.isVital | Boolean | Indicates if the domain is considered vital. |
| CSCDomainManager.Domain.Configuration.multiLocked | Boolean | Indicates if the domain is multilocked. |
| CSCDomainManager.Domain.Configuration.numLiveMx | Number | The number of live MX records for the domain. |
| CSCDomainManager.Domain.Configuration.numRootA | Number | The number of root A records for the domain. |
| CSCDomainManager.Domain.Configuration.numRootTxt | Number | The number of root TXT records for the domain. |
| CSCDomainManager.Domain.Configuration.numSslNetcraft | Number | The number of SSL certificates detected by Netcraft for the domain. |
| CSCDomainManager.Domain.Configuration.numWwwA | Number | The number of WWW A records for the domain. |
| CSCDomainManager.Domain.Configuration.numWwwCname | Number | The number of WWW CNAME records for the domain. |
| CSCDomainManager.Domain.Configuration.regEmail | String | The registration email address for the domain. |
| CSCDomainManager.Domain.Configuration.regName | String | The registration name for the domain. |
| CSCDomainManager.Domain.Configuration.regOrg | String | The registration organization for the domain. |
| CSCDomainManager.Domain.Configuration.registryExpiryDate | Date | The expiration date of the domain registration in the registry. |
| CSCDomainManager.Domain.Configuration.rootHttpCode | Number | The HTTP response code for the root domain. |
| CSCDomainManager.Domain.Configuration.rootHttpUrl | Unknown | The HTTP URL for the root domain. |
| CSCDomainManager.Domain.Configuration.rootIsUrlf | Boolean | Indicates if the root domain is URL forwarding enabled. |
| CSCDomainManager.Domain.Configuration.serverDeleteProhibited | Unknown | Indicates if the domain is prohibited from deletion by the server. |
| CSCDomainManager.Domain.Configuration.serverTransferProhibited | Boolean | Indicates if the domain is prohibited from transfer by the server. |
| CSCDomainManager.Domain.Configuration.serverUpdateProhibited | Boolean | Indicates if the domain is prohibited from updates by the server. |
| CSCDomainManager.Domain.Configuration.techEmail | String | The technical contact email address for the domain. |
| CSCDomainManager.Domain.Configuration.techName | String | The technical contact name for the domain. |
| CSCDomainManager.Domain.Configuration.techOrg | String | The technical contact organization for the domain. |
| CSCDomainManager.Domain.Configuration.tld | String | The top-level domain (TLD) of the domain. |
| CSCDomainManager.Domain.Configuration.urlfTraffic12moAve | Number | The average URL forwarding traffic over the last 12 months. |
| CSCDomainManager.Domain.Configuration.valueRootA | Number | The value of root A records for the domain. |
| CSCDomainManager.Domain.Configuration.valueRootMx | Number | The value of root MX records for the domain. |
| CSCDomainManager.Domain.Configuration.valueRootTxt | Number | The value of root TXT records for the domain. |
| CSCDomainManager.Domain.Configuration.valueWwwA | Number | The value of WWW A records for the domain. |
| CSCDomainManager.Domain.Configuration.valueWwwCname | Number | The value of WWW CNAME records for the domain. |
| CSCDomainManager.Domain.Configuration.wwwHttpCode | String | The HTTP response code for the WWW domain. |
| CSCDomainManager.Domain.Configuration.wwwHttpUrl | String | The HTTP URL for the WWW domain. |
| CSCDomainManager.Domain.Configuration.wwwIsUrlf | Boolean | Indicates if the WWW domain is URL forwarding enabled. |
