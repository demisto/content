This integration provides API access to the SecurityTrails platform.
This integration was integrated and tested with V1 of SecurityTrails

## Configure SecurityTrails in Cortex


| **Parameter** | **Required** |
| --- | --- |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Fetch indicators | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### securitytrails-get-subdomains
***
Returns child and sibling subdomains for a given hostname.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`securitytrails-get-subdomains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname. | Required | 
| children_only | Only return children subdomains. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.name | string | Hostname | 
| SecurityTrails.Domain.subdomains | unknown | Subdomains | 
| Domain.Name | string | Domain name | 
| Domain.Subdomains | string | Subdomains | 
| SecurityTrails.Domain.subdomain_count | number | Subdomain Count | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-domain-details
***
Returns the current data about the given hostname. In addition to the current data, you also get the current statistics associated with a particular record. For example, for a records you'll get how many other hostnames have the same IP.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`securitytrails-get-domain-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.name | string | Domain name | 
| SecurityTrails.Domain.alexa_rank | number | Alexa rank | 
| SecurityTrails.Domain.apex_domain | string | Apex domain | 
| SecurityTrails.Domain.current_dns | unknown | Current DNS records | 
| SecurityTrails.Domain.subdomain_count | number | Subdomain count | 
| Domain.Name | string | Domain name | 
| Domain.NameServers | string | Name servers | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-tags
***
Returns tags for a given hostname


#### Base Command

`securitytrails-get-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.name | string | Domain name | 
| SecurityTrails.Domain.tags | unknown | Domain tags | 
| Domain.Name | string | Domain name | 
| Domain.Tags | string | Domain tags | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-company-details
***
Returns details for a company domain.


#### Base Command

`securitytrails-get-company-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.name | string | Domain name | 
| SecurityTrails.Domain.company | string | Company name | 
| Domain.Name | string | Domain name | 
| Domain.Organization | string | Organization | 
| Domain.Registrant.Name | string | Domain registrant name | 
| WHOIS.Registrant.Name | string | Domain registrant name | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-company-associated-ips
***
Returns associated IPs for a company domain. The data is based on whois data with the names matched to the domains.


#### Base Command

`securitytrails-get-company-associated-ips`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.name | string | Domain name | 
| SecurityTrails.Domain.assocaitedips | unknown | Associated IPs | 
| SecurityTrails.Domain.assocaitedip_count | number | Associated IP Count | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-domain-whois
***
Returns the current WHOIS data about a given hostname with the stats merged together


#### Base Command

`securitytrails-get-domain-whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.expiresDate | date | Expires date | 
| SecurityTrails.Domain.nameServers | unknown | Name servers | 
| SecurityTrails.Domain.updatedDate | date | Updated date | 
| SecurityTrails.Domain.name | string | Domain name | 
| SecurityTrails.Domain.status | string | Status | 
| SecurityTrails.Domain.contacts.countryCode | string | Country code | 
| SecurityTrails.Domain.contacts.organization_count | number | Organization count | 
| SecurityTrails.Domain.contacts.telephone | string | Telephone | 
| SecurityTrails.Domain.contacts.postalCode_count | number | Postal code count | 
| SecurityTrails.Domain.contacts.fax_count | number | Fax count | 
| SecurityTrails.Domain.contacts.street1 | string | Street 1 | 
| SecurityTrails.Domain.contacts.state | string | State | 
| SecurityTrails.Domain.contacts.organization | string | Organization | 
| SecurityTrails.Domain.contacts.telephone_count | number | Telephone count | 
| SecurityTrails.Domain.contacts.country | string | Country | 
| SecurityTrails.Domain.contacts.postalCode | string | Postcode | 
| SecurityTrails.Domain.contacts.type | string | Type | 
| SecurityTrails.Domain.contacts.city_count | number | City count | 
| SecurityTrails.Domain.contacts.name_count | number | Name count | 
| SecurityTrails.Domain.contacts.email | string | Email | 
| SecurityTrails.Domain.contacts.fax | string | Fax | 
| SecurityTrails.Domain.contacts.street1_count | number | Street 1 count | 
| SecurityTrails.Domain.private_registration | boolean | Private registration | 
| SecurityTrails.Domain.createdDate | date | Created date | 
| SecurityTrails.Domain.registrarName | string | Registrar name | 
| SecurityTrails.Domain.contactEmail | string | Contact email | 
| Domain.Admin.Country | string | Country | 
| Domain.Admin.Email | string | Email | 
| Domain.Admin.Name | string | Name | 
| Domain.Admin.Phone | string | Phone | 
| Domain.DomainStatus | string | Status | 
| Domain.Name | string | Name | 
| Domain.NameServers | string | Name server | 
| Domain.UpdatedDate | date | Updated date | 
| Domain.WHOIS.CreationDate | date | Creation date | 
| Domain.WHOIS.DomainStatus | string | Status | 
| Domain.WHOIS.ExpirationDate | date | Expiration date | 
| Domain.WHOIS.NameServers | string | Name servers | 
| Domain.WHOIS.Registrar.Name | string | Name | 
| Domain.WHOIS.UpdatedDate | date | Updated date | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-dns-history
***
Lists out specific historical information about the given hostname parameter. In addition of fetching the historical data for a particular type, the count statistic is returned as well, which represents the number of that particular resource against current data.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`securitytrails-get-dns-history`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname. | Required | 
| type | Type. Possible values are: a, aaaa, mx, ns, soa, txt. Default is a. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.a_history_records.first_seen | string | First seen | 
| SecurityTrails.Domain.a_history_records.last_seen | string | Last seen | 
| SecurityTrails.Domain.a_history_records.organizations | unknown | Organizations | 
| SecurityTrails.Domain.a_history_records.type | string | Type | 
| SecurityTrails.Domain.a_history_records.values.ip | string | IP | 
| SecurityTrails.Domain.a_history_records.values.ipv6 | string | IPv6 | 
| SecurityTrails.Domain.mx_history_records.values.host | string | Host | 
| SecurityTrails.Domain.mx_history_records.values.mx_count | number | MX count | 
| SecurityTrails.Domain.mx_history_records.values.priority | number | Priority | 
| SecurityTrails.Domain.name | string | Name | 
| SecurityTrails.Domain.ns_history_records.values.nameserver | string | Name server | 
| SecurityTrails.Domain.ns_history_records.values.nameserver_count | number | Name server count | 
| SecurityTrails.Domain.soa_history_records.values.email | string | Email | 
| SecurityTrails.Domain.soa_history_records.values.email_count | number | Email count | 
| SecurityTrails.Domain.soa_history_records.values.ttl | number | TTL | 
| SecurityTrails.Domain.txt_history_records.values.value | string | Value | 
| SecurityTrails.Domain.a_history_record_pages | number | A record pages count | 
| SecurityTrails.Domain.aaaa_history_record_pages | number | AAAA record pages count | 
| SecurityTrails.Domain.mx_history_record_pages | number | MX record pages count | 
| SecurityTrails.Domain.ns_history_record_pages | number | NS record pages count | 
| SecurityTrails.Domain.soa_history_record_pages | number | SOA record pages count | 
| SecurityTrails.Domain.txt_history_record_pages | number | TXT record pages count | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-whois-history
***
Returns historical WHOIS information about the given domain.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`securitytrails-get-whois-history`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname. | Required | 
| page | The page of the returned results, starting at 1. A page returns 100 results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.name | string | Name | 
| SecurityTrails.Domain.whois_history.contact.telephone | string | Telephone | 
| SecurityTrails.Domain.whois_history.contact.city | string | City | 
| SecurityTrails.Domain.whois_history.contact.name | string | Name | 
| SecurityTrails.Domain.whois_history.contact.street1 | string | Street 1 | 
| SecurityTrails.Domain.whois_history.contact.state | string | State | 
| SecurityTrails.Domain.whois_history.contact.organization | string | Organization | 
| SecurityTrails.Domain.whois_history.contact.country | string | Country | 
| SecurityTrails.Domain.whois_history.contact.postalCode | string | Postal code | 
| SecurityTrails.Domain.whois_history.contact.type | string | Type | 
| SecurityTrails.Domain.whois_history.contact.email | string | Email | 
| SecurityTrails.Domain.whois_history.contact.fax | string | Fax | 
| SecurityTrails.Domain.whois_history.started | number | Started | 
| SecurityTrails.Domain.whois_history.expiresDate | number | Expires date | 
| SecurityTrails.Domain.whois_history.domain | string | Domain | 
| SecurityTrails.Domain.whois_history.nameServers | string | Name servers | 
| SecurityTrails.Domain.whois_history.gtld | boolean | GTLD | 
| SecurityTrails.Domain.whois_history.updatedDate | number | Updated date | 
| SecurityTrails.Domain.whois_history.status | string | Status | 
| SecurityTrails.Domain.whois_history.full_domain | string | Full domain | 
| SecurityTrails.Domain.whois_history.createdDate | number | Created date | 
| SecurityTrails.Domain.whois_history.registrarName | string | Registrar name | 
| SecurityTrails.Domain.whois_history.ended | number | Ended date | 
| SecurityTrails.Domain.whois_history_count | number | WHOIS history count | 
| Domain.Name | string | Name | 
| Domain.WHOIS/History.Admin.Email | string | Email | 
| Domain.WHOIS/History.Admin.Name | string | Name | 
| Domain.WHOIS/History.Admin.Phone | string | Phone | 
| Domain.WHOIS/History.CreationDate | date | Creation date | 
| Domain.WHOIS/History.DomainStatus | string | Status | 
| Domain.WHOIS/History.ExpirationDate | date | Expiration date | 
| Domain.WHOIS/History.NameServers | string | Name servers | 
| Domain.WHOIS/History.Registrant.Email | string | Email | 
| Domain.WHOIS/History.Registrant.Name | string | Name | 
| Domain.WHOIS/History.Registrant.Phone | string | Phone | 
| Domain.WHOIS/History.Registrar.Email | string | Email | 
| Domain.WHOIS/History.Registrar.Name | string | Name | 
| Domain.WHOIS/History.Registrar.Phone | string | Phone | 
| Domain.WHOIS/History.UpdatedDate | date | Updated date | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-ip-neighbors
***
Returns the neighbors in any given IP level range and essentially allows you to explore closeby IP addresses. It will divide the range into 16 groups. Example: a /28 would be divided into 16 /32 blocks or a /24 would be divided into 16 /28 blocks


#### Base Command

`securitytrails-get-ip-neighbors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipaddress | Starting IP address (optionally with CIDR subnet mask). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.IP.ip | string | IP address | 
| SecurityTrails.IP.block.active_egress | boolean | Active Egress | 
| SecurityTrails.IP.block.hostnames | string | Hostnames | 
| SecurityTrails.IP.block.ports | number | Port | 
| SecurityTrails.IP.block.sites | number | Sites | 
| IP.Address | string | Address | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-search-domain
***
Filter and search specific records using DSL - a powerful SQL like query interface to the data via certain API end points.


#### Base Command

`securitytrails-search-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_ips | Resolves any A records and additionally returns IP addresses. Possible values are: false, true. Default is false. | Optional | 
| page | The page of the returned results, starting at 1. A page returns 100 results. | Optional | 
| scroll | Request scrolling. Only supported when query is used and not filter. See the Scrolling API endpoint. Possible values are: false, true. Default is false. | Optional | 
| query | The DSL query you want to run (https://docs.securitytrails.com/docs/how-to-use-the-dsl). | Optional | 
| filter | JSON dicitonary of filter terms (https://docs.securitytrails.com/reference#domain-search). Can not be used together with query. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.Search.alexa_rank | number | Alexa rank | 
| SecurityTrails.Domain.Search.computed.company_name | string | Company name | 
| SecurityTrails.Domain.Search.host_provider | string | Host provider | 
| SecurityTrails.Domain.Search.hostname | string | Hostname | 
| SecurityTrails.Domain.Search.mail_provider.[0] | string | Mail provider | 
| SecurityTrails.Domain.Search.whois.createdDate | number | Created date | 
| SecurityTrails.Domain.Search.whois.expiresDate | number | Expires date | 
| SecurityTrails.Domain.Search.whois.registrar | string | Registrar | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-statistics-domain
***
Domain statistics


#### Base Command

`securitytrails-statistics-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The DSL query you want to run (https://docs.securitytrails.com/docs/how-to-use-the-dsl). | Optional | 
| filter | JSON dicitonary of filter terms (https://docs.securitytrails.com/reference#domain-search). Can not be used together with query. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.Search.DomainStats.domain_count | number | Domain count | 
| SecurityTrails.Domain.Search.DomainStats.hostname_count.relation | string | Relation | 
| SecurityTrails.Domain.Search.DomainStats.hostname_count.value | number | Value | 
| SecurityTrails.Domain.Search.DomainStats.tld_count | number | TLD count | 
| SecurityTrails.Domain.Search.DomainStats.top_organizations.count | number | Count | 
| SecurityTrails.Domain.Search.DomainStats.top_organizations.key | string | Key | 
| SecurityTrails.Domain.Search.DomainStats.whois_organization_count | number | WHOIS count | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-associated-domains
***
Find all domains that are related to a hostname you input. Limited to 10000 results.


#### Base Command

`securitytrails-get-associated-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname. | Required | 
| page | The page of the returned results, starting at 1. A page returns 100 results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.Domain.associated_domains.alexa_rank | number | Alexa Rank | 
| SecurityTrails.Domain.associated_domains.computed.company_name | string | Company Name | 
| SecurityTrails.Domain.associated_domains.host_provider | string | Host Provider | 
| SecurityTrails.Domain.associated_domains.hostname | string | Hostname | 
| SecurityTrails.Domain.associated_domains.mail_provider | string | Mail Provider | 
| SecurityTrails.Domain.associated_domains.whois.createdDate | number | Created Date | 
| SecurityTrails.Domain.associated_domains.whois.expiresDate | number | Expires Date | 
| SecurityTrails.Domain.associated_domains.whois.registrar | string | Registrar | 
| SecurityTrails.Domain.associated_domain_count | number | Associated Domain Count | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-search-ip
***
Search for IP addresses. A maximum of 10000 results can be retrieved.


#### Base Command

`securitytrails-search-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page of the returned results, starting at 1. A page returns 100 results. Default is 1. | Optional | 
| query | The DSL query you want to run (https://docs.securitytrails.com/docs/how-to-use-the-dsl). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.IP.Search.ip | string | IP Address | 
| SecurityTrails.IP.Search.ports.port | number | Port | 
| SecurityTrails.IP.Search.ports.date_checked | number | Date checked | 
| SecurityTrails.IP.Search.ptr | string | PTR Record | 
| IP.Address | string | Address | 
| IP.Hostname | string | Hostname | 
| IP.Ports | string | Ports | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-statistics-ip
***
Statistics like Reverse DNS pattern identification (RDNS entries are grouped and displayed as x), ports (number of open ports found) or total results are returned


#### Base Command

`securitytrails-statistics-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The DSL query you want to run (https://docs.securitytrails.com/docs/how-to-use-the-dsl). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.IP.Search.IPStats.ports.count | number | Count | 
| SecurityTrails.IP.Search.IPStats.ports.key | number | Key | 
| SecurityTrails.IP.Search.IPStats.top_ptr_patterns.count | number | Count | 
| SecurityTrails.IP.Search.IPStats.top_ptr_patterns.key | string | Key | 
| SecurityTrails.IP.Search.IPStats.total.relation | string | Relation | 
| SecurityTrails.IP.Search.IPStats.total.value | number | Value | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-ip-whois
***
Returns IPs information based on whois information.


#### Base Command

`securitytrails-get-ip-whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipaddress | IP Address. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.IP.contact_email | string | Email | 
| SecurityTrails.IP.contacts.email | string | Email | 
| SecurityTrails.IP.contacts.organization | string | Organization | 
| SecurityTrails.IP.contacts.telephone | string | Telephone | 
| SecurityTrails.IP.contacts.type | string | Type | 
| SecurityTrails.IP.ip | string | IP | 
| SecurityTrails.IP.source | string | Source | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-get-useragents
***
Fetch user agents seen during the last 30 days for a specific IPv4 address. It shows devices with egressing traffic based on large scale web server logs. The number of results is not limited.


#### Base Command

`securitytrails-get-useragents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipaddress | IP Address. | Required | 
| page | The page of the returned results, starting at 1. A page returns 100 results. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityTrails.IP.ip | string | IP Address | 
| SecurityTrails.IP.useragent_records_count | number | Count | 
| SecurityTrails.IP.useragents.browser_family | string | Browser Family | 
| SecurityTrails.IP.useragents.client.engine | string | Client Engine | 
| SecurityTrails.IP.useragents.client.engine_version | string | Client Engine Version | 
| SecurityTrails.IP.useragents.client.name | string | Client Engine Name | 
| SecurityTrails.IP.useragents.client.type | string | Client Engine Type | 
| SecurityTrails.IP.useragents.client.version | string | Client Version | 
| SecurityTrails.IP.useragents.device.brand | string | Device Brand | 
| SecurityTrails.IP.useragents.device.model | string | Device Model | 
| SecurityTrails.IP.useragents.device.type | string | Device Type | 
| SecurityTrails.IP.useragents.lastseen | string | Last Seen | 
| SecurityTrails.IP.useragents.os.name | string | OS Name | 
| SecurityTrails.IP.useragents.os.platform | string | OS Platform | 
| SecurityTrails.IP.useragents.os.version | string | OS Version | 
| SecurityTrails.IP.useragents.os_family | string | OS Family | 
| SecurityTrails.IP.useragents.user_agent | string | User Agent | 


#### Command Example
``` ```

#### Human Readable Output



### domain
***
Provides data enrichment for domains.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to enrich. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.DNS | String | A list of IP objects resolved by DNS. | 
| Domain.DomainStatus | Datte | The status of the domain. | 
| Domain.NameServers | Unknown | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Subdomains | Unknown | \(List&lt;String&gt;\) Subdomains of the domain. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Registrant.Email | String | The email address of the registrant. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.Tags | Unknown | \(List\) Tags of the domain. | 
| Domain.WHOIS.DomainStatus | String | The status of the domain. | 
| Domain.WHOIS.NameServers | String | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.WHOIS.CreationDate | Date | The date that the domain was created. | 
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated. | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. | 
| Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: \`GoDaddy\` | 
| Domain.WHOIS.Registrar.Email | String | The email address of the contact. | 
| Domain.WHOIS.Registrar.Phone | String | The phone number of contact. | 
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. | 
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. | 
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-sql-query
***
Queries the SecurityTrails SQL endpoint. The SecurityTrails SQL API provides a powerful SQL-like query interface to data via certain API endpoints. For a full reference of properties and operators please check the following link: https://securitytrails.com/reference/sql


#### Base Command

`securitytrails-sql-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sql | The SQL query to execute (example: SELECT attribute FROM table WHERE condition = "value"). Possible values are: . | Required | 
| timeout | Read timeout for calls (default is 20 seconds). Possible values are: . Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securitytrails.SQL.total | Number | The total number of hits discovered | 
| Securitytrails.SQL.records | Unknown | The records returned | 
| Securitytrails.SQL.id | String | The ID to use for further GET calls to retrieve more results | 
| Securitytrails.SQL.query | String | The original query used | 
| Securitytrails.SQL.pages | Number | The total number of pages that would need to be called to retrieve the rest of the results | 


#### Command Example
``` ```

#### Human Readable Output



### securitytrails-sql-get-next
***
Retrieves the next page of results returned from a SQL query where the results exceeded the last page.


#### Base Command

`securitytrails-sql-get-next`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID to use to retrieve the next page of results. Possible values are: . | Required | 
| timeout | Read timeout for calls (default is 20 seconds). Possible values are: . Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securitytrails.SQL.total | number | The total number of hits discovered | 
| Securitytrails.SQL.records | unknown | The records returned | 
| Securitytrails.SQL.id | string | The ID to use for further GET calls to retrieve more results | 
| Securitytrails.SQL.query | string | The original query used | 


#### Command Example
``` ```

#### Human Readable Output

