Domain name, DNS and Internet OSINT-based cyber threat intelligence and cybercrime forensics products and data

## Configure DomainTools in Cortex


| **Parameter** | **Required** |
| --- | --- |
| DomainTools API URL | True |
| API Username | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### domain
***
Retrieve domain information.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to check reputation. | Required | 
| long | Should we return full response with detected URLs. | Optional | 
| sampleSize | The number of samples from each type (resolutions, detections, etc.) to display for long format. | Optional | 
| threshold | If number of positive detected domains is bigger than the threshold we will consider it malicious. | Optional | 
| wait | Wait time between tries if we reach the API rate limit in seconds. | Optional | 
| retries | Number of retries for API rate limit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | The tested domain | 
| Domain.RiskScore | unknown | The reputation returned from DomainTools | 
| Domain.Malicious.Vendor | unknown | For malicious domains, the vendor that made the decision | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| DBotScore.Score | unknown | The actual score. | 


#### Command Example
``` ```

#### Human Readable Output



### domainSearch
***
Search for domain based on the given parameters

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domainSearch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | (mandatory and default) Query strings. Each term in the query string must be at least three characters long. Use spaces to separate multiple terms. | Required | 
| pageNumber | Sets the page of results to retrieve from the server. Each page is limited to 100 results. Default: 1. Default is 1. | Optional | 
| maxLength | Limit the maximum domain character count. Default: 25. Default is 25. | Optional | 
| minLength | Limit the minimum domain character count. Default: 1. Default is 1. | Optional | 
| hesHyphen | (true or false) Return results with hyphens in the domain name. Default: true. | Optional | 
| exclude | Terms to exclude from matching. | Optional | 
| activeOnly | (true or false) Return only domains currently registered.Default: false. Possible values are: true, false. Default is false. | Optional | 
| deletedOnly | (true or false) Return only domains previously registered but not currently registered. Default: false. Possible values are: true, false. Default is false. | Optional | 
| anchorLeft | (true or false) Return only domains that start with the query term. Default: false. Possible values are: true, false. Default is false. | Optional | 
| anchorRight | (true or false) Return only domains that end with the query term. Default: false. Possible values are: true, false. Default is false. | Optional | 
| hasNumber | (true or false) Return results with numbers in the domain name. Default: true. Possible values are: false, true. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Domain found by command | 


#### Command Example
``` ```

#### Human Readable Output



### reverseIP
***
Reverse loopkup of an IP address


#### Base Command

`reverseIP`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | (default) specify IP address. | Optional | 
| domain | If you provide a domain name, DomainTools will respond with the list of other domains that share the same IP. | Optional | 
| limit | Limits the size of the domain list than can appear in a response. The limit is applied per-IP address, not for the entire request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Domain name | 
| Domain.DNS.Address | unknown | IP address | 


#### Command Example
``` ```

#### Human Readable Output



### reverseNameServer
***
Reverse nameserver lookup


#### Base Command

`reverseNameServer`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nameServer | (default and mandatory) specify the name of the primary or secondary name server. | Required | 
| limit | Limit the size of the domain list than can appear in a response. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Name of domain | 


#### Command Example
``` ```

#### Human Readable Output



### reverseWhois
***
Reverse lookup of whois information


#### Base Command

`reverseWhois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| terms | (mandatory and default) List of one or more terms to search for in the Whois record, separated with the pipe character ( \| ). | Required | 
| exclude | Domain names with Whois records that match these terms will be excluded from the result set. Separate multiple terms with the pipe character ( \| ). | Optional | 
| onlyHistoricScope | Show only historic records. Possible values are: true, false. Default is false. | Optional | 
| quoteMode | Only lists the size and retail price of the query if you have per-domain pricing access purchase : includes the complete list of domain names that match the query. Default is purchase. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Name of domain | 


#### Command Example
``` ```

#### Human Readable Output



### whois
***
Provides registration details about a domain


#### Base Command

`whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | (mandatory and default) enter domain (do not use full URL). e.g. !whois [query=]demisto.com. | Required | 
| parsed | Should return parsed or raw response. Default is true. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Requested domain name | 
| Domain.Whois | unknown | Whois data | 


#### Command Example
``` ```

#### Human Readable Output



### whoisHistory
***
Display a history of whois for a given domain


#### Base Command

`whoisHistory`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Specify domain e.g. mycompany.com. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Name of domain | 
| Domain.WhoisHistory | unknown | Domain Whois history data | 


#### Command Example
``` ```

#### Human Readable Output



### domainProfile
***
Display profile for a given domain


#### Base Command

`domainProfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Specify domain e.g. mycompany.com. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output

