CyberTotal is a cloud-based threat intelligence service developed by CyCraft.
This integration was integrated and tested with version xx of CyberTotal
## Configure CyberTotal on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CyberTotal.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | CyberTotal URL | True |
| token | CyberTotal API Token | True |
| feed | Fetch indicators | False |
| threshold_ip | Bad ip threshold | False |
| threshold_file | Bad hash threshold | False |
| threshold_domain | Bad domain threshold | False |
| threshold_url | Bad url threshold | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Return IP information and reputation


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 
| threshold | If the IP has reputation above the threshold then the IP defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.IP.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.IP.resource | string |  The scan target sent to CyberTotal. | 
| CyberTotal.IP.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.IP.permalink | string | The link of this IP’s report in CyberTotal. | 
| CyberTotal.IP.severity | number | Severity of this IP. The range is from 0 to 10. | 
| CyberTotal.IP.confidence | number | Confidence of this IP. The range is from 0 to 10. | 
| CyberTotal.IP.threat | string | Threat of this IP, which is a select from ‘High’, ‘Medium’ and ‘Low’. | 
| CyberTotal.IP.detection_engines | number | The number of all antivirus vendors scanned. | 
| CyberTotal.IP.positive_detections | number | The number of antivirus vendors scanned with positive detection. | 
| CyberTotal.IP.detection_ratio | string | The ratio of positive\_detections and detection\_engines. | 
| CyberTotal.IP.message | string | Message about this search. | 


#### Command Example
``` ```

#### Human Readable Output



### file
***
Return file's information and reputation


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | list of hash(s). | Required | 
| threshold | If the HASH has reputation above the threshold then the HASH defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 
| file |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.File.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS | 
| CyberTotal.File.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.File.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.File.permalink | string | The link of this HASH’s report in CyberTotal. | 
| CyberTotal.File.severity | number | Severity of this HASH. The range is from 0 to 10. | 
| CyberTotal.File.confidence | number | Confidence of this HASH. The range is from 0 to 10. | 
| CyberTotal.File.threat | string | Threat of this HASH, which is a select from ‘High’, ‘Medium’ and ‘Low’. | 
| CyberTotal.File.detection_engines | number | The number of all antivirus vendors scanned. | 
| CyberTotal.File.positive_detections | number | The number of antivirus vendors scanned with positive detection. | 
| CyberTotal.File.detection_ratio | string | The ratio of positive\_detections and detection\_engines. | 
| CyberTotal.File.message | string | Message about this search. | 
| CyberTotal.File.size | string | Size of this file. | 
| CyberTotal.File.md5 | string | This file’s md5 value. | 
| CyberTotal.File.sha1 | string | This file’s sha1 value. | 
| CyberTotal.File.sha256 | string | This file’s sha256 value. | 
| CyberTotal.File.extension | string | This file’s extension type. | 
| CyberTotal.File.name | string | This file’s name, separated by ‘,’ if more than 2 names. | 


#### Command Example
``` ```

#### Human Readable Output



### domain
***
Return domain  information and reputation


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains. | Required | 
| threshold | If the domain has reputation above the threshold then the domain defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.Domain.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.Domain.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.Domain.permalink | string | The link of this domain’s report in CyberTotal. | 
| CyberTotal.Domain.severity | number | Severity of this domain. The range is from 0 to 10. | 
| CyberTotal.Domain.confidence | number | Confidence of this domain. The range is from 0 to 10. | 
| CyberTotal.Domain.threat | string | Threat of this domain, which is a select from ‘High’, ‘Medium’ and ‘Low’. | 
| CyberTotal.Domain.detection_engines | number | The number of all antivirus vendors scanned. | 
| CyberTotal.Domain.positive_detections | number | The number of antivirus vendors scanned with positive detection. | 
| CyberTotal.Domain.detection_ratio | string | The ratio of positive\_detections and detection\_engines. | 
| CyberTotal.Domain.message | string | Message about this search. | 


#### Command Example
``` ```

#### Human Readable Output



### url
***
Return domain information and reputation


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of url(s). | Required | 
| threshold | If the URL has reputation above the threshold then the URL defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.URL.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.URL.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.URL.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.URL.permalink | string | The link of this URL’s report in CyberTotal. | 
| CyberTotal.URL.severity | number | Severity of this URL. The range is from 0 to 10. | 
| CyberTotal.URL.confidence | number | Confidence of this URL. The range is from 0 to 10. | 
| CyberTotal.URL.threat | string | Threat of this URL, which is a select from ‘High’, ‘Medium’ and ‘Low’. | 
| CyberTotal.URL.detection_engines | number | The number of all antivirus vendors scanned. | 
| CyberTotal.URL.positive_detections | number | The number of antivirus vendors scanned with positive detection. | 
| CyberTotal.URL.detection_ratio | string | The ratio of positive\_detections and detection\_engines. | 
| CyberTotal.URL.message | string | Message about this search. | 


#### Command Example
``` ```

#### Human Readable Output



### cybertotal-ip-whois
***
Return ip whois information


#### Base Command

`cybertotal-ip-whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IP(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.WHOIS-IP.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.WHOIS-IP.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.WHOIS-IP.message | string | Message about this search. | 
| CyberTotal.WHOIS-IP.permalink | string | The link of this whois report in CyberTotal. | 
| CyberTotal.WHOIS-IP.createdAt | date | Create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.updatedAt | date | Update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.status | string | Status of this IP | 
| CyberTotal.WHOIS-IP.domain | string | Domain of this IP | 
| CyberTotal.WHOIS-IP.domainMd5 | string | MD5 translation of CyberTotal.WHOIS\-IP.domain | 
| CyberTotal.WHOIS-IP.domainUnicode | string | Encode CyberTotal.WHOIS\-IP.domain by using unicode | 
| CyberTotal.WHOIS-IP.nameservers | string | An array of all DNS nameservers | 
| CyberTotal.WHOIS-IP.registrarName | string | The name of registrar | 
| CyberTotal.WHOIS-IP.registrarEmail | string | The email address of registrar | 
| CyberTotal.WHOIS-IP.registrarPhone | string | The phone number of registrar | 
| CyberTotal.WHOIS-IP.registrarCreatedAt | date | Registrar create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.registrarUpdatedAt | date | Registrar update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.registrarExpiresAt | date | Registrar expire date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.registrant.name | string | The name of registrant | 
| CyberTotal.WHOIS-IP.registrant.organization | string | The organization name of registrant | 
| CyberTotal.WHOIS-IP.registrant.street | string | The street name of registrant | 
| CyberTotal.WHOIS-IP.registrant.city | string | The location city of registrant | 
| CyberTotal.WHOIS-IP.registrant.state | string | The location state name of registrant | 
| CyberTotal.WHOIS-IP.registrant.zip | string | The post zip code of registrant | 
| CyberTotal.WHOIS-IP.registrant.country | string | The country of registrant | 
| CyberTotal.WHOIS-IP.registrant.address | string | The address of registrant | 
| CyberTotal.WHOIS-IP.admin.name | string | The name of admin | 
| CyberTotal.WHOIS-IP.admin.organization | string | The organization name of admin | 
| CyberTotal.WHOIS-IP.admin.street | string | The street name of admin | 
| CyberTotal.WHOIS-IP.admin.city | string | The location city of admin | 
| CyberTotal.WHOIS-IP.admin.state | string | The location state name of admin | 
| CyberTotal.WHOIS-IP.admin.zip | string | The post zip code of admin | 
| CyberTotal.WHOIS-IP.admin.country | string | The country of admin | 
| CyberTotal.WHOIS-IP.admin.address | string | The address of admin | 
| CyberTotal.WHOIS-IP.technical.name | string | The name of technical | 
| CyberTotal.WHOIS-IP.technical.organization | string | The organization name of technical | 
| CyberTotal.WHOIS-IP.technical.street | string | The street name of technical | 
| CyberTotal.WHOIS-IP.technical.city | string | The location city of technical | 
| CyberTotal.WHOIS-IP.technical.state | string | The location state name of technical | 
| CyberTotal.WHOIS-IP.technical.zip | string | The post zip code of technical | 
| CyberTotal.WHOIS-IP.technical.country | string | The country of technical | 
| CyberTotal.WHOIS-IP.technical.address | string | The address of technical | 
| CyberTotal.WHOIS-IP.contactEmails | string | An array of all contact email address | 
| CyberTotal.WHOIS-IP.contacts | string | An array of all contact details | 
| CyberTotal.WHOIS-IP.contactNames | string | An array of all contact names | 
| CyberTotal.WHOIS-IP.contactCountries | string | An array of all contact countries | 
| CyberTotal.WHOIS-IP.domainAvailable | boolean | If this domain is available | 
| CyberTotal.WHOIS-IP.expired | boolean | If this IP is expired | 


#### Command Example
``` ```

#### Human Readable Output



### cybertotal-url-whois
***
Return url whois information


#### Base Command

`cybertotal-url-whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URL(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.WHOIS-URL.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.WHOIS-URL.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.WHOIS-URL.message | string | Message about this search. | 
| CyberTotal.WHOIS-URL.permalink | string | The link of this whois report in CyberTotal. | 
| CyberTotal.WHOIS-URL.createdAt | date | Create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.updatedAt | date | Update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.status | string | Status of this IP | 
| CyberTotal.WHOIS-URL.domain | string | Domain of this IP | 
| CyberTotal.WHOIS-URL.domainMd5 | string | MD5 translation of CyberTotal.WHOIS\-URL.domain | 
| CyberTotal.WHOIS-URL.domainUnicode | string | Encode CyberTotal.WHOIS\-URL.domain by using unicode | 
| CyberTotal.WHOIS-URL.nameservers | string | An array of all DNS nameservers | 
| CyberTotal.WHOIS-URL.registrarName | string | The name of registrar | 
| CyberTotal.WHOIS-URL.registrarEmail | string | The email address of registrar | 
| CyberTotal.WHOIS-URL.registrarPhone | string | The phone number of registrar | 
| CyberTotal.WHOIS-URL.registrarCreatedAt | date | Registrar create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.registrarUpdatedAt | date | Registrar update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.registrarExpiresAt | date | Registrar expire date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.registrant.name | string | The name of registrant | 
| CyberTotal.WHOIS-URL.registrant.organization | string | The organization name of registrant | 
| CyberTotal.WHOIS-URL.registrant.street | string | The street name of registrant | 
| CyberTotal.WHOIS-URL.registrant.city | string | The location city of registrant | 
| CyberTotal.WHOIS-URL.registrant.state | string | The location state name of registrant | 
| CyberTotal.WHOIS-URL.registrant.zip | string | The post zip code of registrant | 
| CyberTotal.WHOIS-URL.registrant.country | string | The country of registrant | 
| CyberTotal.WHOIS-URL.registrant.address | string | The address of registrant | 
| CyberTotal.WHOIS-URL.admin.name | string | The name of admin | 
| CyberTotal.WHOIS-URL.admin.organization | string | The organization name of admin | 
| CyberTotal.WHOIS-URL.admin.street | string | The street name of admin | 
| CyberTotal.WHOIS-URL.admin.city | string | The location city of admin | 
| CyberTotal.WHOIS-URL.admin.state | string | The location state name of admin | 
| CyberTotal.WHOIS-URL.admin.zip | string | The post zip code of admin | 
| CyberTotal.WHOIS-URL.admin.country | string | The country of admin | 
| CyberTotal.WHOIS-URL.admin.address | string | The address of admin | 
| CyberTotal.WHOIS-URL.technical.name | string | The name of technical | 
| CyberTotal.WHOIS-URL.technical.organization | string | The organization name of technical | 
| CyberTotal.WHOIS-URL.technical.street | string | The street name of technical | 
| CyberTotal.WHOIS-URL.technical.city | string | The location city of technical | 
| CyberTotal.WHOIS-URL.technical.state | string | The location state name of technical | 
| CyberTotal.WHOIS-URL.technical.zip | string | The post zip code of technical | 
| CyberTotal.WHOIS-URL.technical.country | string | The country of technical | 
| CyberTotal.WHOIS-URL.technical.address | string | The address of technical | 
| CyberTotal.WHOIS-URL.contactEmails | string | An array of all contact email address | 
| CyberTotal.WHOIS-URL.contacts | string | An array of all contact details | 
| CyberTotal.WHOIS-URL.contactNames | string | An array of all contact names | 
| CyberTotal.WHOIS-URL.contactCountries | string | An array of all contact countries | 
| CyberTotal.WHOIS-URL.domainAvailable | boolean | If this domain is available | 
| CyberTotal.WHOIS-URL.expired | boolean | If this URL is expired | 


#### Command Example
``` ```

#### Human Readable Output



### cybertotal-domain-whois
***
Return domain whois information


#### Base Command

`cybertotal-domain-whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domain(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.WHOIS-Domain.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.WHOIS-Domain.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.WHOIS-Domain.message | string | Message about this search. | 
| CyberTotal.WHOIS-Domain.permalink | string | The link of this whois report in CyberTotal. | 
| CyberTotal.WHOIS-Domain.createdAt | date | Create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.updatedAt | date | Update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.status | string | Status of this Domain | 
| CyberTotal.WHOIS-Domain.domain | string | Top level Domain of this domain | 
| CyberTotal.WHOIS-Domain.domainMd5 | string | MD5 translation of CyberTotal.WHOIS\-Domain.domain | 
| CyberTotal.WHOIS-Domain.domainUnicode | string | Encode CyberTotal.WHOIS\-Domain.domain by using unicode | 
| CyberTotal.WHOIS-Domain.nameservers | string | An array of all DNS nameservers | 
| CyberTotal.WHOIS-Domain.registrarName | string | The name of registrar | 
| CyberTotal.WHOIS-Domain.registrarEmail | string | The email address of registrar | 
| CyberTotal.WHOIS-Domain.registrarPhone | string | The phone number of registrar | 
| CyberTotal.WHOIS-Domain.registrarCreatedAt | date | Registrar create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.registrarUpdatedAt | date | Registrar update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.registrarExpiresAt | date | Registrar expire date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.registrant.name | string | The name of registrant | 
| CyberTotal.WHOIS-Domain.registrant.organization | string | The organization name of registrant | 
| CyberTotal.WHOIS-Domain.registrant.street | string | The street name of registrant | 
| CyberTotal.WHOIS-Domain.registrant.city | string | The location city of registrant | 
| CyberTotal.WHOIS-Domain.registrant.state | string | The location state name of registrant | 
| CyberTotal.WHOIS-Domain.registrant.zip | string | The post zip code of registrant | 
| CyberTotal.WHOIS-Domain.registrant.country | string | The country of registrant | 
| CyberTotal.WHOIS-Domain.registrant.address | string | The address of registrant | 
| CyberTotal.WHOIS-Domain.admin.name | string | The name of admin | 
| CyberTotal.WHOIS-Domain.admin.organization | string | The organization name of admin | 
| CyberTotal.WHOIS-Domain.admin.street | string | The street name of admin | 
| CyberTotal.WHOIS-Domain.admin.city | string | The location city of admin | 
| CyberTotal.WHOIS-Domain.admin.state | string | The location state name of admin | 
| CyberTotal.WHOIS-Domain.admin.zip | string | The post zip code of admin | 
| CyberTotal.WHOIS-Domain.admin.country | string | The country of admin | 
| CyberTotal.WHOIS-Domain.admin.address | string | The address of admin | 
| CyberTotal.WHOIS-Domain.technical.name | string | The name of technical | 
| CyberTotal.WHOIS-Domain.technical.organization | string | The organization name of technical | 
| CyberTotal.WHOIS-Domain.technical.street | string | The street name of technical | 
| CyberTotal.WHOIS-Domain.technical.city | string | The location city of technical | 
| CyberTotal.WHOIS-Domain.technical.state | string | The location state name of technical | 
| CyberTotal.WHOIS-Domain.technical.zip | string | The post zip code of technical | 
| CyberTotal.WHOIS-Domain.technical.country | string | The country of technical | 
| CyberTotal.WHOIS-Domain.technical.address | string | The address of technical | 
| CyberTotal.WHOIS-Domain.contactEmails | string | An array of all contact email address | 
| CyberTotal.WHOIS-Domain.contacts | string | An array of all contact details | 
| CyberTotal.WHOIS-Domain.contactNames | string | An array of all contact names | 
| CyberTotal.WHOIS-Domain.contactCountries | string | An array of all contact countries | 
| CyberTotal.WHOIS-Domain.domainAvailable | boolean | If this domain is available | 
| CyberTotal.WHOIS-Domain.expired | boolean | If this domain is expired | 


#### Command Example
``` ```

#### Human Readable Output


