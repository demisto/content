CSCDomainManager
This integration was integrated and tested with version xx of CSCDomainManager.

## Configure CSCDomainManager on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CSCDomainManager.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL |  | True |
    | Token | The token to use for connection | True |
    | API Key | The API Key to use for connection | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| filter | can write your own filter according to ?. | Optional | 
| sort | sorting the output by ?. | Optional | 
| page | first page to show ?. | Optional | 
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
| CSCDomainManager.Domain.account.accountName | String |  | 
| CSCDomainManager.Domain.account.accountNumber | String |  | 
| CSCDomainManager.Domain.brandName | String |  | 
| CSCDomainManager.Domain.businessUnit | String |  | 
| CSCDomainManager.Domain.countryCode | String |  | 
| CSCDomainManager.Domain.criticalDomain | Boolean |  | 
| CSCDomainManager.Domain.customFields.name | String |  | 
| CSCDomainManager.Domain.customFields.value | String |  | 
| CSCDomainManager.Domain.dnssecActivated | String |  | 
| CSCDomainManager.Domain.extension | String |  | 
| CSCDomainManager.Domain.idn | String |  | 
| CSCDomainManager.Domain.idnReferenceName | String |  | 
| CSCDomainManager.Domain.lastModifiedDate | Date |  | 
| CSCDomainManager.Domain.lastModifiedDescription | String |  | 
| CSCDomainManager.Domain.lastModifiedReason | String |  | 
| CSCDomainManager.Domain.localAgent | Boolean |  | 
| CSCDomainManager.Domain.newGtld | Boolean |  | 
| CSCDomainManager.Domain.serverDeleteProhibited | Boolean |  | 
| CSCDomainManager.Domain.serverTransferProhibited | Boolean |  | 
| CSCDomainManager.Domain.serverUpdateProhibited | Boolean |  | 
| CSCDomainManager.Domain.urlf.redirectType | String |  | 
| CSCDomainManager.Domain.urlf.urlForwarding | Boolean |  | 
| CSCDomainManager.Domain.whoisContacts.city | String |  | 
| CSCDomainManager.Domain.whoisContacts.contactType | String |  | 
| CSCDomainManager.Domain.whoisContacts.country | String |  | 
| CSCDomainManager.Domain.whoisContacts.email | String |  | 
| CSCDomainManager.Domain.whoisContacts.fax | String |  | 
| CSCDomainManager.Domain.whoisContacts.firstName | String |  | 
| CSCDomainManager.Domain.whoisContacts.lastName | String |  | 
| CSCDomainManager.Domain.whoisContacts.organization | String |  | 
| CSCDomainManager.Domain.whoisContacts.phone | String |  | 
| CSCDomainManager.Domain.whoisContacts.phoneExtn | String |  | 
| CSCDomainManager.Domain.whoisContacts.postalCode | String |  | 
| CSCDomainManager.Domain.whoisContacts.stateProvince | String |  | 
| CSCDomainManager.Domain.whoisContacts.street1 | String |  | 
| CSCDomainManager.Domain.whoisContacts.street2 | String |  | 
| CSCDomainManager.Domain.whoisPrivacy | Boolean |  | 

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

#### Base Command

`csc-domains-availability-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | the domain name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCDomainManager.Domain.Availability.qualifiedDomainName | String |  | 
| CSCDomainManager.Domain.Availability.result.code | String |  | 
| CSCDomainManager.Domain.Availability.result.message | String |  | 
| CSCDomainManager.Domain.Availability.basePrice.price | String |  | 
| CSCDomainManager.Domain.Availability.basePrice.currency | String |  | 
| CSCDomainManager.Domain.Availability.listOfTheTerms | String |  | 
| CSCDomainManager.Domain.Availability.availableTerms | Unknown |  | 

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

#### Base Command

`csc-domains-configuration-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | domain name to filter by, can start with like=, in=. | Optional | 
| registration_date | registration date to filter by, can start with gt=, ge=, lt=, le=. Date example 22-Apr-2024. | Optional | 
| domain_email | email to filter by, can start with like=, in=. | Optional | 
| filter | can write your own filter according to ?. | Optional | 
| page | first page to show ?. | Optional | 
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
| CSCDomainManager.Domain.Configuration.account.accountName | String |  | 
| CSCDomainManager.Domain.Configuration.account.accountNumber | String |  | 
| CSCDomainManager.Domain.Configuration.adminOrg | String |  | 
| CSCDomainManager.Domain.Configuration.businessUnit | String |  | 
| CSCDomainManager.Domain.Configuration.dnsData.dnsDomain | String |  | 
| CSCDomainManager.Domain.Configuration.dnsData.dnsProvider | String |  | 
| CSCDomainManager.Domain.Configuration.dnsHostingType | String |  | 
| CSCDomainManager.Domain.Configuration.dnsTraffic12moAve | Number |  | 
| CSCDomainManager.Domain.Configuration.extension | String |  | 
| CSCDomainManager.Domain.Configuration.hasCscUrlf | Boolean |  | 
| CSCDomainManager.Domain.Configuration.hasDkim | Boolean |  | 
| CSCDomainManager.Domain.Configuration.hasDmarc | Boolean |  | 
| CSCDomainManager.Domain.Configuration.hasDnssecDs | Boolean |  | 
| CSCDomainManager.Domain.Configuration.hasSpf | Boolean |  | 
| CSCDomainManager.Domain.Configuration.hasWww | Boolean |  | 
| CSCDomainManager.Domain.Configuration.isGtld | Boolean |  | 
| CSCDomainManager.Domain.Configuration.isLive | Boolean |  | 
| CSCDomainManager.Domain.Configuration.isLiveType | String |  | 
| CSCDomainManager.Domain.Configuration.isMultilockEligible | Boolean |  | 
| CSCDomainManager.Domain.Configuration.isVital | Boolean |  | 
| CSCDomainManager.Domain.Configuration.multiLocked | Boolean |  | 
| CSCDomainManager.Domain.Configuration.numLiveMx | Number |  | 
| CSCDomainManager.Domain.Configuration.numRootA | Number |  | 
| CSCDomainManager.Domain.Configuration.numRootTxt | Number |  | 
| CSCDomainManager.Domain.Configuration.numSslNetcraft | Number |  | 
| CSCDomainManager.Domain.Configuration.numWwwA | Number |  | 
| CSCDomainManager.Domain.Configuration.numWwwCname | Number |  | 
| CSCDomainManager.Domain.Configuration.regEmail | String |  | 
| CSCDomainManager.Domain.Configuration.regName | String |  | 
| CSCDomainManager.Domain.Configuration.regOrg | String |  | 
| CSCDomainManager.Domain.Configuration.registryExpiryDate | Date |  | 
| CSCDomainManager.Domain.Configuration.rootHttpCode | Number |  | 
| CSCDomainManager.Domain.Configuration.rootHttpUrl | Unknown |  | 
| CSCDomainManager.Domain.Configuration.rootIsUrlf | Boolean |  | 
| CSCDomainManager.Domain.Configuration.serverDeleteProhibited | Unknown |  | 
| CSCDomainManager.Domain.Configuration.serverTransferProhibited | Unknown |  | 
| CSCDomainManager.Domain.Configuration.serverUpdateProhibited | Unknown |  | 
| CSCDomainManager.Domain.Configuration.techEmail | String |  | 
| CSCDomainManager.Domain.Configuration.techName | String |  | 
| CSCDomainManager.Domain.Configuration.techOrg | String |  | 
| CSCDomainManager.Domain.Configuration.tld | String |  | 
| CSCDomainManager.Domain.Configuration.urlfTraffic12moAve | Number |  | 
| CSCDomainManager.Domain.Configuration.valueRootA | Unknown |  | 
| CSCDomainManager.Domain.Configuration.valueRootMx | Unknown |  | 
| CSCDomainManager.Domain.Configuration.valueRootTxt | Unknown |  | 
| CSCDomainManager.Domain.Configuration.valueWwwA | Unknown |  | 
| CSCDomainManager.Domain.Configuration.valueWwwCname | Unknown |  | 
| CSCDomainManager.Domain.Configuration.wwwHttpCode | Number |  | 
| CSCDomainManager.Domain.Configuration.wwwHttpUrl | Unknown |  | 
| CSCDomainManager.Domain.Configuration.wwwIsUrlf | Boolean |  | 

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
| CSCDomainManager.Domain.customFields.value | String |  | 
| CSCDomainManager.Domain.dnsType | String |  | 
| CSCDomainManager.Domain.dnssecActivated | String |  | 
| CSCDomainManager.Domain.domain | String |  | 
| CSCDomainManager.Domain.extension | String |  | 
| CSCDomainManager.Domain.idn | String |  | 
| CSCDomainManager.Domain.idnReferenceName | String |  | 
| CSCDomainManager.Domain.lastModifiedDate | Date |  | 
| CSCDomainManager.Domain.lastModifiedDescription | String |  | 
| CSCDomainManager.Domain.lastModifiedReason | String |  | 
| CSCDomainManager.Domain.localAgent | Boolean |  | 
| CSCDomainManager.Domain.managedStatus | String |  | 
| CSCDomainManager.Domain.nameServers | String |  | 
| CSCDomainManager.Domain.newGtld | Boolean |  | 
| CSCDomainManager.Domain.paidThroughDate | Date |  | 
| CSCDomainManager.Domain.qualifiedDomainName | String |  | 
| CSCDomainManager.Domain.registrationDate | Date |  | 
| CSCDomainManager.Domain.registryExpiryDate | Date |  | 
| CSCDomainManager.Domain.serverDeleteProhibited | Boolean |  | 
| CSCDomainManager.Domain.serverTransferProhibited | Boolean |  | 
| CSCDomainManager.Domain.serverUpdateProhibited | Boolean |  | 
| CSCDomainManager.Domain.urlf.redirectType | String |  | 
| CSCDomainManager.Domain.urlf.urlForwarding | Boolean |  | 
| CSCDomainManager.Domain.whoisContacts.city | String |  | 
| CSCDomainManager.Domain.whoisContacts.contactType | String |  | 
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

