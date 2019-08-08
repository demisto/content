## Overview
---
Use the Whois integration to enrich domain indicators.

## Use Cases
---
* Research on malicious url.

## Configure JsonWhoIs on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for JsonWhoIs.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __API Token__
    * __Use system proxy__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. whois
### 1. whois
---
Provides data enrichment for Domains, URLs, and IP addresses.

##### Base Command

`whois`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | URL, IP, or domain to be enriched | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.WHOIS.DomainStatus | Boolean | Domain | 
| Domain.WHOIS.NameServers | String | Name servers | 
| Domain.WHOIS.CreationDate | Date | Creation date | 
| Domain.WHOIS.UpdatedDate | Date | Updated date | 
| Domain.WHOIS.ExpirationDate | Date | Expiration date | 
| Domain.WHOIS.Registrant.Name | String | Registrant name | 
| Domain.WHOIS.Registrant.Email | String | Registrant email | 
| Domain.WHOIS.Registrant.Phone | String | Registrant phone | 
| Domain.WHOIS.Registrar.Name | String | Registrar name | 
| Domain.WHOIS.Registrar.Email	 | String | Registrar email | 
| Domain.WHOIS.Registrar.Phone | String | Registrar phone | 
| Domain.WHOIS.Admin.Name | String | Admin name | 
| Domain.WHOIS.Admin.Email | String | Admin email | 
| Domain.WHOIS.Admin.Phone | String | Admin phone | 


##### Command Example
```!whois query=demisto.com```

##### Context Example
```
{
    "Domain": {
        "WHOIS": {
            "UpdatedDate": "2019-05-14T16:14:12.000Z", 
            "CreationDate": "2015-01-16T21:36:27.000Z", 
            "ExpirationDate": "2026-01-16T21:36:27.000Z", 
            "DomainStatus": "registered"
        }
    }
}{
    "Domain": {
        "WHOIS": {
            "UpdatedDate": "2019-05-14T16:14:12.000Z", 
            "CreationDate": "2015-01-16T21:36:27.000Z", 
            "ExpirationDate": "2026-01-16T21:36:27.000Z", 
            "DomainStatus": "registered"
        }
    }
}
```

##### Human Readable Output
### Admin account
|Email|Name|Phone|
|---|---|---|
|mail account |WhoisGuard Protected|+507.8365503|
### Name servers
|name|
|---|
|pns31.cloudns.net|
|pns32.cloudns.net|
|pns33.cloudns.net|
|pns34.cloudns.net|
### Registrar
|Name|
|---|
|NameCheap, Inc.|
### Registrant
|Email|Name|Phone|
|---|---|---|
|mail account |WhoisGuard Protected|+507.8365503|
### Others
|CreationDate|DomainStatus|ExpirationDate|UpdatedDate|
|---|---|---|---|
|2015-01-16T21:36:27.000Z|registered|2026-01-16T21:36:27.000Z|2019-05-14T16:14:12.000Z|

## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* API isn't stable, somtimes return status code 500.
