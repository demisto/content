Leverage the power of Sixgill to supercharge Cortex XSOAR with real-time Threat Intelligence indicators. Enrich IOCs such as domains, URLs, hashes, and IP addresses straight from the XSOAR platform.
This integration was integrated and tested with Sixgill clients.
## Configure Sixgill_Darkfeed_Enrichment on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Sixgill_Darkfeed_Enrichment.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | client_id | Sixgill API client ID | True |
    | client_secret | Sixgill API client secret | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Return IP information and reputation


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of ip's. | Required | 
| skip | No. of indicators which need to be skipped while returning the result set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.IP.created | Date | Creation timestamp of IOC | 
| SixgillDarkfeed.IP.id | String | Unique ID of IOC | 
| SixgillDarkfeed.IP.description | String | Description of IOC | 
| SixgillDarkfeed.IP.lang | String | Language of original post in Sixgill portal | 
| SixgillDarkfeed.IP.modified | Date | Modification timestamp of IOC | 
| SixgillDarkfeed.IP.pattern | String | IOC hash/domain/IP address. hashes include MD5, SHA-1 and SHA-256 when possible | 
| SixgillDarkfeed.IP.sixgill_actor | String | Actor of original post on dark web | 
| SixgillDarkfeed.IP.sixgill_confidence | Number | Confidence score | 
| SixgillDarkfeed.IP.sixgill_feedid | String | Subfeed ID | 
| SixgillDarkfeed.IP.sixgill_feedname | String | Subfeed name | 
| SixgillDarkfeed.IP.sixgill_postid | String | ID of post in Sixgill portal | 
| SixgillDarkfeed.IP.sixgill_posttitle | String | Title of post in Sixgill portal | 
| SixgillDarkfeed.IP.sixgill_severity | Number | Severity score | 
| SixgillDarkfeed.IP.sixgill_source | String | Source of post in Sixgill portal | 
| SixgillDarkfeed.IP.spec_version | String | STIX specification version | 
| SixgillDarkfeed.IP.type | String | STIX object type | 
| SixgillDarkfeed.IP.valid_from | Date | Post creation date in Sixgill portal | 
| SixgillDarkfeed.IP.labels | Unknown | Indicative labels of IOC | 
| SixgillDarkfeed.IP.external_reference | Unknown | Link to IOC on Virustotal and abstraction of number of detections; Mitre ATT&amp;CK tatics and techniques | 
| IP.Address | String | IP address. | 


#### Command Example
``` ```

#### Human Readable Output



### domain
***
Return Domain information and reputation


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | domain name. | Required | 
| skip | No. of indicators which need to be skipped while returning the result set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.Domain.created | Date | Creation timestamp of IOC | 
| SixgillDarkfeed.Domain.id | String | Unique ID of IOC | 
| SixgillDarkfeed.Domain.description | String | Description of IOC | 
| SixgillDarkfeed.Domain.lang | String | Language of original post in Sixgill portal | 
| SixgillDarkfeed.Domain.modified | Date | Modification timestamp of IOC | 
| SixgillDarkfeed.Domain.pattern | String | IOC hash/domain/IP address. hashes include MD5, SHA-1 and SHA-256 when possible | 
| SixgillDarkfeed.Domain.sixgill_actor | String | Actor of original post on dark web | 
| SixgillDarkfeed.Domain.sixgill_confidence | Number | Confidence score | 
| SixgillDarkfeed.Domain.sixgill_feedid | String | Subfeed ID | 
| SixgillDarkfeed.Domain.sixgill_feedname | String | Subfeed name | 
| SixgillDarkfeed.Domain.sixgill_postid | String | ID of post in Sixgill portal | 
| SixgillDarkfeed.Domain.sixgill_posttitle | String | Title of post in Sixgill portal | 
| SixgillDarkfeed.Domain.sixgill_severity | Number | Severity score | 
| SixgillDarkfeed.Domain.sixgill_source | String | Source of post in Sixgill portal | 
| SixgillDarkfeed.Domain.spec_version | String | STIX specification version | 
| SixgillDarkfeed.Domain.type | String | STIX object type | 
| SixgillDarkfeed.Domain.valid_from | Date | Post creation date in Sixgill portal | 
| SixgillDarkfeed.Domain.labels | Unknown | Indicative labels of IOC | 
| SixgillDarkfeed.Domain.external_reference | Unknown | Link to IOC on Virustotal and abstraction of number of detections; Mitre ATT&amp;CK tatics and techniques | 
| Domain.Name | String | Domain name. | 


#### Command Example
``` ```

#### Human Readable Output



### url
***
Return URL information and reputation


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URL's. | Required | 
| skip | No. of indicators which need to be skipped while returning the result set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.URL.created | Date | Creation timestamp of IOC | 
| SixgillDarkfeed.URL.id | String | Unique ID of IOC | 
| SixgillDarkfeed.URL.description | String | Description of IOC | 
| SixgillDarkfeed.URL.lang | String | Language of original post in Sixgill portal | 
| SixgillDarkfeed.URL.modified | Date | Modification timestamp of IOC | 
| SixgillDarkfeed.URL.pattern | String | IOC hash/domain/IP address. hashes include MD5, SHA-1 and SHA-256 when possible | 
| SixgillDarkfeed.URL.sixgill_actor | String | Actor of original post on dark web | 
| SixgillDarkfeed.URL.sixgill_confidence | Number | Confidence score | 
| SixgillDarkfeed.URL.sixgill_feedid | String | Subfeed ID | 
| SixgillDarkfeed.URL.sixgill_feedname | String | Subfeed name | 
| SixgillDarkfeed.URL.sixgill_postid | String | ID of post in Sixgill portal | 
| SixgillDarkfeed.URL.sixgill_posttitle | String | Title of post in Sixgill portal | 
| SixgillDarkfeed.URL.sixgill_severity | Number | Severity score | 
| SixgillDarkfeed.URL.sixgill_source | String | Source of post in Sixgill portal | 
| SixgillDarkfeed.URL.spec_version | String | STIX specification version | 
| SixgillDarkfeed.URL.type | String | STIX object type | 
| SixgillDarkfeed.URL.valid_from | Date | Post creation date in Sixgill portal | 
| SixgillDarkfeed.URL.labels | Unknown | Indicative labels of IOC | 
| URL.Data | string | URL name. | 
| SixgillDarkfeed.URL.external_reference | Unknown | Link to IOC on Virustotal and abstraction of number of detections; Mitre ATT&amp;CK tatics and techniques | 


#### Command Example
``` ```

#### Human Readable Output



### file
***
Return file information and reputation


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of File Hash's. | Required | 
| skip | No. of indicators which need to be skipped while returning the result set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.File.created | Date | Creation timestamp of IOC | 
| SixgillDarkfeed.File.id | String | Unique ID of IOC | 
| SixgillDarkfeed.File.description | String | Description of IOC | 
| SixgillDarkfeed.File.lang | String | Language of original post in Sixgill portal | 
| SixgillDarkfeed.File.modified | Date | Modification timestamp of IOC | 
| SixgillDarkfeed.File.pattern | String | IOC hash/domain/IP address. hashes include MD5, SHA-1 and SHA-256 when possible | 
| SixgillDarkfeed.File.sixgill_actor | String | Actor of original post on dark web | 
| SixgillDarkfeed.File.sixgill_confidence | Number | Confidence score | 
| SixgillDarkfeed.File.sixgill_feedid | String | Subfeed ID | 
| SixgillDarkfeed.File.sixgill_feedname | String | Subfeed name | 
| SixgillDarkfeed.File.sixgill_postid | String | ID of post in Sixgill portal | 
| SixgillDarkfeed.File.sixgill_posttitle | String | Title of post in Sixgill portal | 
| SixgillDarkfeed.File.sixgill_severity | Number | Severity score | 
| SixgillDarkfeed.File.sixgill_source | String | Source of post in Sixgill portal | 
| SixgillDarkfeed.File.spec_version | String | STIX specification version | 
| SixgillDarkfeed.File.type | String | STIX object type | 
| SixgillDarkfeed.File.valid_from | Date | Post creation date in Sixgill portal | 
| SixgillDarkfeed.File.labels | Unknown | Indicative labels of IOC | 
| SixgillDarkfeed.File.external_reference | Unknown | Link to IOC on Virustotal and abstraction of number of detections; Mitre ATT&amp;CK tatics and techniques | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.SHA512 | string | SHA512 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.MD5 | string | MD5 hash of the file. | 


#### Command Example
``` ```

#### Human Readable Output



### actor
***
Query the Sixgill Darkfeed and receive all IOCs shared by that threat actor


#### Base Command

`actor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actor | List of actor's. | Required | 
| skip | No. of indicators which need to be skipped while returning the result set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.Actor.created | Date | Creation timestamp of IOC | 
| SixgillDarkfeed.Actor.id | String | Unique ID of IOC | 
| SixgillDarkfeed.Actor.description | String | Description of IOC | 
| SixgillDarkfeed.Actor.lang | String | Language of original post in Sixgill portal | 
| SixgillDarkfeed.Actor.modified | Date | Modification timestamp of IOC | 
| SixgillDarkfeed.Actor.pattern | String | IOC hash/domain/IP address. hashes include MD5, SHA-1 and SHA-256 when possible | 
| SixgillDarkfeed.Actor.sixgill_actor | String | Actor of original post on dark web | 
| SixgillDarkfeed.Actor.sixgill_confidence | Number | Confidence score | 
| SixgillDarkfeed.Actor.sixgill_feedid | String | Subfeed ID | 
| SixgillDarkfeed.Actor.sixgill_feedname | String | Subfeed name | 
| SixgillDarkfeed.Actor.sixgill_postid | String | ID of post in Sixgill portal | 
| SixgillDarkfeed.Actor.sixgill_posttitle | String | Title of post in Sixgill portal | 
| SixgillDarkfeed.Actor.sixgill_severity | Number | Severity score | 
| SixgillDarkfeed.Actor.sixgill_source | String | Source of post in Sixgill portal | 
| SixgillDarkfeed.Actor.spec_version | String | STIX specification version | 
| SixgillDarkfeed.Actor.type | String | STIX object type | 
| SixgillDarkfeed.Actor.valid_from | Date | Post creation date in Sixgill portal | 
| SixgillDarkfeed.Actor.labels | Unknown | Indicative labels of IOC | 
| SixgillDarkfeed.Actor.external_reference | Unknown | Link to IOC on Virustotal and abstraction of number of detections; Mitre ATT&amp;CK tatics and techniques | 


#### Command Example
``` ```

#### Human Readable Output



### post_id
***
Query the Sixgill Darkfeed for a specific Sixgill post ID (i.e. unique identifier of a specific post shared in the underground) and receive all IOCs shared in that post


#### Base Command

`post_id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| post_id | List of postid's. | Required | 
| skip | No. of indicators which need to be skipped while returning the result set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.Postid.created | Date | Creation timestamp of IOC | 
| SixgillDarkfeed.Postid.id | String | Unique ID of IOC | 
| SixgillDarkfeed.Postid.description | String | Description of IOC | 
| SixgillDarkfeed.Postid.lang | String | Language of original post in Sixgill portal | 
| SixgillDarkfeed.Postid.modified | Date | Modification timestamp of IOC | 
| SixgillDarkfeed.Postid.pattern | String | IOC hash/domain/IP address. hashes include MD5, SHA-1 and SHA-256 when possible | 
| SixgillDarkfeed.Postid.sixgill_actor | String | Actor of original post on dark web | 
| SixgillDarkfeed.Postid.sixgill_confidence | Number | Confidence score | 
| SixgillDarkfeed.Postid.sixgill_feedid | String | Subfeed ID | 
| SixgillDarkfeed.Postid.sixgill_feedname | String | Subfeed name | 
| SixgillDarkfeed.Postid.sixgill_postid | String | ID of post in Sixgill portal | 
| SixgillDarkfeed.Postid.sixgill_posttitle | String | Title of post in Sixgill portal | 
| SixgillDarkfeed.Postid.sixgill_severity | Number | Severity score | 
| SixgillDarkfeed.Postid.sixgill_source | String | Source of post in Sixgill portal | 
| SixgillDarkfeed.Postid.spec_version | String | STIX specification version | 
| SixgillDarkfeed.Postid.type | String | STIX object type | 
| SixgillDarkfeed.Postid.valid_from | Date | Post creation date in Sixgill portal | 
| SixgillDarkfeed.Postid.labels | Unknown | Indicative labels of IOC | 
| SixgillDarkfeed.Postid.external_reference | Unknown | Link to IOC on Virustotal and abstraction of number of detections; Mitre ATT&amp;CK tatics and techniques | 


#### Command Example
``` ```

#### Human Readable Output


