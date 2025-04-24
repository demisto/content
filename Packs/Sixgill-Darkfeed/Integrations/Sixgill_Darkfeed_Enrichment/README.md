Leverage the power of Sixgill to supercharge Cortex XSOAR with real-time Threat Intelligence indicators. Enrich IOCs such as domains, URLs, hashes, and IP addresses straight from XSOAR platform.
This integration was integrated and tested with sixgill-clients

## Configure Sixgill_Darkfeed_Enrichment in Cortex



| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| client_id | Sixgill API client ID | True |
| client_secret | Sixgill API client secret | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Returns information and a reputation for each IP in the input list.


#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IPs to check. | Required | 
| skip | The number of outputs per indicator to be skipped when returning the result set. Default is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The score of the indicator. | 
| DBotScore.Type | String | Indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.IP.created | Date | The timestamp when the indicator was created. | 
| SixgillDarkfeed.IP.id | String | The unique ID of the indicator. | 
| SixgillDarkfeed.IP.description | String | The description of the indicator. | 
| SixgillDarkfeed.IP.lang | String | The language of the original post in the Sixgill portal. | 
| SixgillDarkfeed.IP.modified | Date | The timestamp when the indicator was last modified. | 
| SixgillDarkfeed.IP.pattern | String | The indicator IP address. | 
| SixgillDarkfeed.IP.sixgill_actor | String | The actor of the original post on the dark web. | 
| SixgillDarkfeed.IP.sixgill_confidence | Number | The indicator confidence score. | 
| SixgillDarkfeed.IP.sixgill_feedid | String | The indicator subfeed ID. | 
| SixgillDarkfeed.IP.sixgill_feedname | String | The indicator subfeed name. | 
| SixgillDarkfeed.IP.sixgill_postid | String | The ID of the post in the Sixgill portal. | 
| SixgillDarkfeed.IP.sixgill_posttitle | String | The title of the post in the Sixgill portal. | 
| SixgillDarkfeed.IP.sixgill_severity | Number | The indicator severity score. | 
| SixgillDarkfeed.IP.sixgill_source | String | The source of the post in the Sixgill portal. | 
| SixgillDarkfeed.IP.spec_version | String | The STIX specification version. | 
| SixgillDarkfeed.IP.type | String | The STIX object type. | 
| SixgillDarkfeed.IP.valid_from | Date | The creation date of the post in the Sixgill portal. | 
| SixgillDarkfeed.IP.labels | Unknown | The indicative labels of the indicator. | 
| SixgillDarkfeed.IP.external_reference | Unknown | Link to the IOC on VirusTotal and an abstraction of the number of detections; MITRE ATT&amp;CK tactics and techniques. | 
| IP.Address | String | The indicator IP address. | 


#### Command Example

``` ```

#### Human Readable Output



### domain

***
Returns information and a reputation for each domain name in the input list.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domain names to check. | Required | 
| skip | The number of outputs per indicator to be skipped when returning the result set. Default is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The score of the indicator. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.Domain.created | Date | The timestamp when the indicator was created. | 
| SixgillDarkfeed.Domain.id | String | The unique ID of the indicator. | 
| SixgillDarkfeed.Domain.description | String | The description of the indicator. | 
| SixgillDarkfeed.Domain.lang | String | The language of the original post in the Sixgill portal. | 
| SixgillDarkfeed.Domain.modified | Date | The timestamp when the indicator was last modified. | 
| SixgillDarkfeed.Domain.pattern | String | The indicator domain name. | 
| SixgillDarkfeed.Domain.sixgill_actor | String | The actor of the original post on the dark web. | 
| SixgillDarkfeed.Domain.sixgill_confidence | Number | The indicator confidence score. | 
| SixgillDarkfeed.Domain.sixgill_feedid | String | The indicator subfeed ID. | 
| SixgillDarkfeed.Domain.sixgill_feedname | String | The indicator subfeed name. | 
| SixgillDarkfeed.Domain.sixgill_postid | String | The ID of the post in the Sixgill portal. | 
| SixgillDarkfeed.Domain.sixgill_posttitle | String | The title of the post in the Sixgill portal. | 
| SixgillDarkfeed.Domain.sixgill_severity | Number | The indicator severity score. | 
| SixgillDarkfeed.Domain.sixgill_source | String | The source of the post in the Sixgill portal. | 
| SixgillDarkfeed.Domain.spec_version | String | The STIX specification version. | 
| SixgillDarkfeed.Domain.type | String | The STIX object type. | 
| SixgillDarkfeed.Domain.valid_from | Date | The creation date of the post in the Sixgill portal. | 
| SixgillDarkfeed.Domain.labels | Unknown | The indicative labels of the indicator. | 
| SixgillDarkfeed.Domain.external_reference | Unknown | Link to the IOC on Virustotal and an abstraction of the number of detections; MITRE ATT&amp;CK tactics and techniques. | 
| Domain.Name | String | The indicator domain name. | 


#### Command Example

``` ```

#### Human Readable Output



### url

***
Returns information and a reputation for each URL in the input list.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to check. | Required | 
| skip | The number of outputs per indicator to be skipped when returning the result set. Default is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The score of the indicator. | 
| DBotScore.Type | String | Indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.URL.created | Date | The timestamp when the indicator was created. | 
| SixgillDarkfeed.URL.id | String | The unique ID of the indicator. | 
| SixgillDarkfeed.URL.description | String | The description of the indicator. | 
| SixgillDarkfeed.URL.lang | String | The language of the original post in the Sixgill portal. | 
| SixgillDarkfeed.URL.modified | Date | The timestamp when the indicator was last modified. | 
| SixgillDarkfeed.URL.pattern | String | The indicator URL. | 
| SixgillDarkfeed.URL.sixgill_actor | String | The actor of the original post on the dark web. | 
| SixgillDarkfeed.URL.sixgill_confidence | Number | The indicator confidence score. | 
| SixgillDarkfeed.URL.sixgill_feedid | String | The indicator subfeed ID. | 
| SixgillDarkfeed.URL.sixgill_feedname | String | The indicator subfeed name. | 
| SixgillDarkfeed.URL.sixgill_postid | String | The ID of the post in the Sixgill portal. | 
| SixgillDarkfeed.URL.sixgill_posttitle | String | The title of the post in the Sixgill portal. | 
| SixgillDarkfeed.URL.sixgill_severity | Number | The indicator severity score. | 
| SixgillDarkfeed.URL.sixgill_source | String | The source of the post in the Sixgill portal. | 
| SixgillDarkfeed.URL.spec_version | String | The STIX specification version. | 
| SixgillDarkfeed.URL.type | String | The STIX object type. | 
| SixgillDarkfeed.URL.valid_from | Date | The creation date of the post in the Sixgill portal. | 
| SixgillDarkfeed.URL.labels | Unknown | The indicative labels of the indicator. | 
| URL.Data | string | The indicator URL. | 
| SixgillDarkfeed.URL.external_reference | Unknown | Link to the IOC on Virustotal and an abstraction of the number of detections; MITRE ATT&amp;CK tactics and techniques. | 


#### Command Example

``` ```

#### Human Readable Output



### file

***
Returns information and a reputation for each file hash in the input list.


#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of file hashes to check. | Required | 
| skip | The number of outputs per indicator to be skipped when returning the result set. Default is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The score of the indicator. | 
| DBotScore.Type | String | Indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| SixgillDarkfeed.File.created | Date | The timestamp when the indicator was created. | 
| SixgillDarkfeed.File.id | String | The unique ID of the indicator. | 
| SixgillDarkfeed.File.description | String | The description of the indicator. | 
| SixgillDarkfeed.File.lang | String | The language of the original post in the Sixgill portal. | 
| SixgillDarkfeed.File.modified | Date | The timestamp when the indicator was last modified. | 
| SixgillDarkfeed.File.pattern | String | The indicator file hash \(hashes include MD5, SHA-1 and SHA-256 when possible\). | 
| SixgillDarkfeed.File.sixgill_actor | String | The actor of the original post on the dark web. | 
| SixgillDarkfeed.File.sixgill_confidence | Number | The indicator confidence score. | 
| SixgillDarkfeed.File.sixgill_feedid | String | The indicator subfeed ID. | 
| SixgillDarkfeed.File.sixgill_feedname | String | The indicator subfeed name. | 
| SixgillDarkfeed.File.sixgill_postid | String | The ID of the post in the Sixgill portal. | 
| SixgillDarkfeed.File.sixgill_posttitle | String | The title of the post in the Sixgill portal. | 
| SixgillDarkfeed.File.sixgill_severity | Number | The indicator severity score. | 
| SixgillDarkfeed.File.sixgill_source | String | The source of the post in the Sixgill portal. | 
| SixgillDarkfeed.File.spec_version | String | The STIX specification version. | 
| SixgillDarkfeed.File.type | String | The STIX object type. | 
| SixgillDarkfeed.File.valid_from | Date | The creation date of the post in the Sixgill portal. | 
| SixgillDarkfeed.File.labels | Unknown | The indicative labels of the indicator. | 
| SixgillDarkfeed.File.external_reference | Unknown | Link to the IOC on Virustotal and an abstraction of the number of detections; MITRE ATT&amp;CK tactics and techniques. | 
| File.SHA256 | string | The SHA256 file hash. | 
| File.SHA512 | string | The SHA512 file hash. | 
| File.SHA1 | string | The SHA1 file hash. | 
| File.MD5 | string | The MD5 file hash. | 


#### Command Example

``` ```

#### Human Readable Output



### sixgill-get-actor

***
Returns information and a reputation for each actor in the input list.


#### Base Command

`sixgill-get-actor`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actor | A comma-separated list of actors to check. | Required | 
| skip | The number of outputs per actor to be skipped when returning the result set. Default is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SixgillDarkfeed.Actor.created | Date | The timestamp when the actor shared their first IOC. | 
| SixgillDarkfeed.Actor.id | String | The unique ID of the actor. | 
| SixgillDarkfeed.Actor.description | String | The description of the actor. | 
| SixgillDarkfeed.Actor.lang | String | The language of the original post in the Sixgill portal. | 
| SixgillDarkfeed.Actor.modified | Date | The timestamp when the actor was last modified. | 
| SixgillDarkfeed.Actor.pattern | String | A list of the IOCs shared by the actor. | 
| SixgillDarkfeed.Actor.sixgill_actor | String | The actor of the original post on the dark web. | 
| SixgillDarkfeed.Actor.sixgill_confidence | Number | The confidence score of the actor. | 
| SixgillDarkfeed.Actor.sixgill_feedid | String | The Subfeed ID of the actor. | 
| SixgillDarkfeed.Actor.sixgill_feedname | String | The Subfeed name of the actor. | 
| SixgillDarkfeed.Actor.sixgill_postid | String | The ID of the post in the Sixgill portal. | 
| SixgillDarkfeed.Actor.sixgill_posttitle | String | The title of the post in the Sixgill portal. | 
| SixgillDarkfeed.Actor.sixgill_severity | Number | The severity score of the actor. | 
| SixgillDarkfeed.Actor.sixgill_source | String | The source of the post in the Sixgill portal. | 
| SixgillDarkfeed.Actor.spec_version | String | The STIX specification version. | 
| SixgillDarkfeed.Actor.type | String | The STIX object type. | 
| SixgillDarkfeed.Actor.valid_from | Date | The creation date of the post in the Sixgill portal. | 
| SixgillDarkfeed.Actor.labels | Unknown | The indicative labels of the actor. | 
| SixgillDarkfeed.Actor.external_reference | Unknown | Link to the IOC on Virustotal and an abstraction of the number of detections; MITRE ATT&amp;CK tactics and techniques. | 


#### Command Example

``` ```

#### Human Readable Output



### sixgill-get-post-id

***
Returns information and a reputation for each post ID in the input list.


#### Base Command

`sixgill-get-post-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| post_id | A comma-separated list of post IDs to check. | Required | 
| skip | The number of outputs per post ID to be skipped when returning the result set. Default is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SixgillDarkfeed.Postid.created | Date | The timestamp when an IOC was first included in the post. | 
| SixgillDarkfeed.Postid.id | String | The unique ID of the post. | 
| SixgillDarkfeed.Postid.description | String | The description of the post ID. | 
| SixgillDarkfeed.Postid.lang | String | The language of the original post in the Sixgill portal. | 
| SixgillDarkfeed.Postid.modified | Date | The timestamp when the post ID information was last modified. | 
| SixgillDarkfeed.Postid.pattern | String | A list of the IOCs included in the post. | 
| SixgillDarkfeed.Postid.sixgill_actor | String | The actor of the original post on the dark web. | 
| SixgillDarkfeed.Postid.sixgill_confidence | Number | The confidence score of the post ID. | 
| SixgillDarkfeed.Postid.sixgill_feedid | String | The Subfeed ID of the post ID. | 
| SixgillDarkfeed.Postid.sixgill_feedname | String | The Subfeed name of the post ID. | 
| SixgillDarkfeed.Postid.sixgill_postid | String | The ID of the post in the Sixgill portal. | 
| SixgillDarkfeed.Postid.sixgill_posttitle | String | The title of the post in the Sixgill portal. | 
| SixgillDarkfeed.Postid.sixgill_severity | Number | The severity score of the post ID. | 
| SixgillDarkfeed.Postid.sixgill_source | String | The source of the post in the Sixgill portal. | 
| SixgillDarkfeed.Postid.spec_version | String | The STIX specification version. | 
| SixgillDarkfeed.Postid.type | String | The STIX object type. | 
| SixgillDarkfeed.Postid.valid_from | Date | The creation date of the post in the Sixgill portal. | 
| SixgillDarkfeed.Postid.labels | Unknown | The indicative labels of the post ID. | 
| SixgillDarkfeed.Postid.external_reference | Unknown | Link to the IOC on Virustotal and an abstraction of the number of detections; MITRE ATT&amp;CK tactics and techniques. | 


#### Command Example

``` ```

#### Human Readable Output

