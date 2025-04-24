FullHunt is the attack surface database of the entire Internet. FullHunt enables companies to discover all of their attack surfaces, monitor them for exposure, and continuously scan them for the latest security vulnerabilities. All, in a single platform, and more.

## Configure FullHunt in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fullhunt-get-account-status

***
Get information about the user account such as company, email, credit, and usage

#### Base Command

`fullhunt-get-account-status`

#### Input

None

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FullHunt.UserInfo.user.company | string | Company name |
|FullHunt.UserInfo.user.email| string | Company email |
|FullHunt.UserInfo.user.first_name| string | First name |
|FullHunt.UserInfo.user.last_name| string | Last name |
|FullHunt.UserInfo.user.plan| string | Fullhunt plan |
|FullHunt.UserInfo.user_credits.credits_usage|number| Credits usage at the time of the request |
|FullHunt.UserInfo.user_credits.max_results_per_request|number| Maximum results per request |
|FullHunt.UserInfo.user_credits.remaining_credits|number| Remaining credits on the account for the current month |
|FullHunt.UserInfo.user_credits.total_credits_per_month|number| Total credits available per month |

### fullhunt-get-host

***
Get host details

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`fullhunt-get-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | Host or list of hosts | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FullHunt.Host.is_cloud | boolean | Whether the host is based on cloud technology or not |  
| FullHunt.Host.network_ports | array | List of open ports |  
| FullHunt.Host.is_live | boolean | Whether the host is live or not |  
| FullHunt.Host.http_title | string | HTTP title |  
| FullHunt.Host.http_status_code | number | HTTP status code |  
| FullHunt.Host.domain | string | Domain |  
| FullHunt.Host.ip_metadata.postal_code | number | Postal code related to the IP |  
| FullHunt.Host.ip_metadata.location_longitude | number | Longitude coordinate of the IP |  
| FullHunt.Host.ip_metadata.isp | string | Internet Service Provider of the IP |  
| FullHunt.Host.ip_metadata.organization | string | Organization of the IP |  
| FullHunt.Host.ip_metadata.country_name | string | Name of the country of the IP |  
| FullHunt.Host.ip_metadata.region | string | Region of the IP |  
| FullHunt.Host.ip_metadata.country_code | string | Two letters country code |  
| FullHunt.Host.ip_metadata.location_latitude | number | Latitude coordinate of the IP |  
| FullHunt.Host.ip_metadata.asn | number | Autonomous System Number | 
| FullHunt.Host.ip_metadata.city_name | string | City name of the IP |  
| FullHunt.Host.has_private_ip | boolean | Whether the host has a private IP listed |  
| FullHunt.Host.is_resolvable | boolean | Whether the host is resolvable |  
| FullHunt.Host.dns.a | array | List of DNS A entries |  
| FullHunt.Host.dns.aaaa | string | DNS AAAA entry |  
| FullHunt.Host.dns.cname | array | List of DNS CNAME entries |  
| FullHunt.Host.dns.mx | array | List of DNS MX entries |  
| FullHunt.Host.dns.ns | array | List of DNS NS entries |  
| FullHunt.Host.dns.ptr | string | DNS PTR entry |  
| FullHunt.Host.dns.txt | string | DNS TXT entry |  
| FullHunt.Host.has_ipv6 | boolean | Whether the host has an IPv6 listed |  
| FullHunt.Host.tld | string | Top Level Domain |  
| FullHunt.Host.cdn | string | Content Delivery Network |  
| FullHunt.Host.is_cloudflare | boolean | Whether host uses Cloudflare or not | 
| FullHunt.Host.cloud.provider | string | Name of the cloud provider |  
| FullHunt.Host.cloud.region | string | Region of the cloud provider |  
| FullHunt.Host.is_cdn | boolean | Whether host uses CDN |  
| FullHunt.Host.tags | array | Tags of the host |  
| FullHunt.Host.ip_address | string | IP address of the host | 

### domain

***
Get details about one specified domain

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`fullhunt-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | One domain to check | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FullHunt.Domain.domain | string | Domain |  
| FullHunt.Domain.hosts | array | List of hosts with same details as running the command "fullhunt-get-host" |  
| FullHunt.Domain.message | string | Message |  
| FullHunt.Domain.metadata.all_results_count | number | Number of results for this API request |  
| FullHunt.Domain.metadata.available_results_for_user | number | Number of results available for the user performing the API request |  
| FullHunt.Domain.metadata.domain | string | Domain |  
| FullHunt.Domain.metadata.last_scanned | number | Epoch timestamp of the domain last scan |  
| FullHunt.Domain.metadata.max_results_for_user | number | Maximum results for the user |  
| FullHunt.Domain.metadata.timestamp | number | Epoch timestamp of the API request |  
| FullHunt.Domain.metadata.user_plan | string | Fullhunt plan |  
| FullHunt.Domain.status | number | HTTP status code |   

### fullhunt-get-subdomain

***
Get all subdomains from a given domain

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`fullhunt-get-subdomain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Enter the domain from which you want to enumerate subdomains. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FullHunt.Subdomain.domain | string | Domain |  
| FullHunt.Subdomain.hosts | array | List of subdomains |  
| FullHunt.Subdomain.message | string | Message |  
| FullHunt.Subdomain.metadata.all_results_count | number | Number of results for this API request |  
| FullHunt.Subdomain.metadata.available_results_for_user | number | Number of results available for the user performing the API request |  
| FullHunt.Subdomain.metadata.domain | string | Domain |  
| FullHunt.Subdomain.metadata.last_scanned | number | Epoch timestamp of the domain last scan |  
| FullHunt.Subdomain.metadata.max_results_for_user | number | Maximum results for the user |  
| FullHunt.Subdomain.metadata.timestamp | number | Epoch timestamp of the API request |  
| FullHunt.Subdomain.metadata.user_plan | string | Fullhunt plan |  
| FullHunt.Subdomain.status | number | HTTP status code |   
