USTA is an Cyber Intelligence Platform that responds directly and effectively to today's complex cyber threats. 

## Configure USTA in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://usta.prodaft.com) |  | True |
| API Key | You can reach out your access token : https://usta.prodaft.com/\#/api-documents | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### usta-get-malicious-urls
***
You can get malicious URLs with this command


#### Base Command

`usta-get-malicious-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | Format type of the returned result. Possible values are: json, stix, stix2, txt. Default is json. | Optional | 
| url | Filtering by URL Address. | Optional | 
| is_domain | You can search only those with or without domain name registration. Possible values are: true, false. Default is true. | Optional | 
| url_type | Filtering by malicious type. | Optional | 
| tag | Filtering by tags. Example: tag=Keitaro. | Optional | 
| start | Starting date(Example: 2021-03-18-13-59 / yy-mm-dd-hh-mm). | Optional | 
| end | End Date(Example: 2021-03-18-13-59 / yy-mm-dd-hh-mm). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.MaliciousUrl.country | unknown | Country | 
| Usta.MaliciousUrl.created | unknown | Created Date | 
| Usta.MaliciousUrl.domain | unknown | Domain | 
| Usta.MaliciousUrl.ip_addresses | unknown | IP Addresses | 
| Usta.MaliciousUrl.is_domain | unknown | Is Domain | 
| Usta.MaliciousUrl.modified | unknown | Modified Date | 
| Usta.MaliciousUrl.tags | unknown | Tags | 
| Usta.MaliciousUrl.threat_type | unknown | Threat Type | 
| Usta.MaliciousUrl.url | unknown | URL | 


#### Command Example
``` ```

#### Human Readable Output



### usta-get-malware-hashs
***
You can get malware hashs with this command


#### Base Command

`usta-get-malware-hashs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | Format type of the returned result. Possible values are: json, stix, stix2. Default is json. | Optional | 
| md5 | Filtering by md5. | Optional | 
| sha1 | Filtering by sha1. | Optional | 
| tag | Filtering by tags. Example: tag=Keitaro. | Optional | 
| start | Starting Date(Example: 2021-03-18-13-59 / yy-mm-dd-hh-mm). | Optional | 
| end | End Date(Example: 2021-03-18-13-59 / yy-mm-dd-hh-mm). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.MalwareHash.created | unknown | Created Date | 
| Usta.MalwareHash.md5 | unknown | MD5 | 
| Usta.MalwareHash.sha1 | unknown | SHA1 | 
| Usta.MalwareHash.tags | unknown | Tags | 
| Usta.MalwareHash.yara_rule | unknown | Yara Rule | 


#### Command Example
``` ```

#### Human Readable Output



### usta-get-phishing-sites
***
You can get phishing sites with this command


#### Base Command

`usta-get-phishing-sites`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Filtering by status. Possible values are: open, close, in_progress, out_of_scope, passive. | Optional | 
| source | Filtering by source(URL). | Optional | 
| page | Paginiation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.PhishingSites.current_page | unknown | Current page | 
| Usta.PhishingSites.last_page | unknown | Last page | 
| Usta.PhishingSites.next_page_url | unknown | Next page URL | 
| Usta.PhishingSites.per_page | unknown | Content count per page | 
| Usta.PhishingSites.prev_page_url | unknown | Prev page URL | 
| Usta.PhishingSites.results | unknown | Results | 
| Usta.PhishingSites.total | unknown | Content count | 
| Usta.PhishingSites.total_pages | unknown | Total Page | 


#### Command Example
``` ```

#### Human Readable Output



### usta-get-identity-leaks
***
With the Identity Leak API, you can access the hashed version of the credentials added to the platform.SHA256(MD5(Identity_Number))


#### Base Command

`usta-get-identity-leaks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Staring Date(Example: 2021-03-18-13-59 / yy-mm-dd-hh-mm). | Optional | 
| end | End Date(Example: 2021-03-18-13-59 / yy-mm-dd-hh-mm). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.IdentityLeaks.created | unknown | Created date | 
| Usta.IdentityLeaks. signature | unknown | Signature | 


#### Command Example
``` ```

#### Human Readable Output



### usta-get-stolen-client-accounts
***
You can access stolen customer accounts via Stolen-Client-accounts API.


#### Base Command

`usta-get-stolen-client-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Filtering by username. | Optional | 
| password | Filtering by password. | Optional | 
| source | It allows to filter the stolen customer accounts detected according to the source.Available values : malware, phishing_site, data_leak, clients. Possible values are: malware, phishing_site, data_leak, clients. | Optional | 
| start | Starting Date(Example: 2021-03-18-13-59 / yy-mm-dd-hh-mm). | Optional | 
| end | End Date(Example: 2021-03-18-13-59 / yy-mm-dd-hh-mm). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.StolenClientAccounts.created | unknown | Created date | 
| Usta.StolenClientAccounts.password | unknown | Password | 
| Usta.StolenClientAccounts.source | unknown | Source | 
| Usta.StolenClientAccounts.url | unknown | URL | 
| Usta.StolenClientAccounts.username | unknown | Username | 


#### Command Example
``` ```

#### Human Readable Output



### usta-get-domain
***
If you want to get more detailed information about malicious domain names, you can use this command.


#### Base Command

`usta-get-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Search with domain name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.Domain.asn_records | unknown | ASN records | 
| Usta.Domain.country | unknown | Country | 
| Usta.Domain.dns_records | unknown | DNS records | 
| Usta.Domain.domain | unknown | Domain | 
| Usta.Domain.ip_addresses | unknown | IP addresses | 
| Usta.Domain.ssl_records | unknown | SSL records | 
| Usta.Domain.whois_records | unknown | Whois records | 


#### Command Example
``` ```

#### Human Readable Output



### usta-get-ip-address
***
If you want to get more detailed information about specific IP Address, you can use this command.


#### Base Command

`usta-get-ip-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | Search with IP Address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.IPAddress.asn_records | unknown | ASN records | 
| Usta.IPAddress.country | unknown | Country | 
| Usta.IPAddress.ip_address | unknown | IP address | 
| Usta.IPAddress.ssl_records | unknown | SSL records | 
| Usta.IPAddress.whois_records | unknown | Whois records | 


#### Command Example
``` ```

#### Human Readable Output



### usta-send-referrer-url
***
You can search about the accuracy of the urls referring to your company's websites.


#### Base Command

`usta-send-referrer-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | URL Value. Example: http://www.google3.com. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.Referrer.error | unknown | If any errors are received, it gives the details of the error | 


#### Command Example
``` ```

#### Human Readable Output



### usta-search-specific-identity-leaks
***
With this command, you can search specific identity number that hashed in leaks 


#### Base Command

`usta-search-specific-identity-leaks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity_number | Search with this identity number. You can search all identity number with "," . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.SpecificLeaks.existing | unknown | If the identity is leaked, you can see it in existing. | 
| Usta.SpecificLeaks.not_existing | unknown | If the identity is not leaked, you can see it in not_existing | 


#### Command Example
``` ```

#### Human Readable Output



### usta-close-incident
***
You can close the notifications in the status of "In Progress" or "Open", which are currently opened to your institution, via API.


#### Base Command

`usta-close-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Incident ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Usta.CloseIncident.id | unknown | If the incident is closed, returns the id value that was closed. | 


#### Command Example
``` ```

#### Human Readable Output

