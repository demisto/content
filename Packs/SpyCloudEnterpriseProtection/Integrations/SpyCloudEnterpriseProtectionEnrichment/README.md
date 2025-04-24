## SpyCloud Enterprise Protection Enrichment

Provide enrichment for domains, IPs, emails, usernames, and passwords using the SpyCloud Enterprise Protection API.

## Configure SpyCloud Enterprise Protection Enrichment in Cortex


| **Parameter** | **Required** |
| --- | --- |
| API URL | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### spycloud-breach-catalog-list

***
List the Breach Catalog. By default, this lists all breaches in SpyCloud. With the arguments, it's possible to scope the results.

#### Base Command

`spycloud-breach-catalog-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to return from the collection. Limit default value is 50. | Optional | 
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. Example:-  YYYY-MM-DD. | Optional | 
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field.<br/> Example:-  YYYY-MM-DD. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| query | Query value to search the breach catalog for. | Optional | 
| all_results | Fetch all results. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.BreachList.site | String | Website of breached organization, when available. | 
| SpyCloud.BreachList.confidence | Number | Numerical score representing the confidence in the source of the breach. | 
| SpyCloud.BreachList.id | Number | Numerical breach ID. This number correlates to source_id data point found in breach records. | 
| SpyCloud.BreachList.acquisition_date | Date | The date on which our security research team first acquired the breached data. | 
| SpyCloud.BreachList.uuid | String | UUID v4 encoded version of breach ID. This is relevant for users of Firehose, where each deliverable \(records file\) is named using the breach UUID. | 
| SpyCloud.BreachList.num_records | Number | Number of records we parsed and ingested from this particular breach. This is after parsing, normalization and deduplication take place. | 
| SpyCloud.BreachList.type | String | Denotes if a breach is considered public or private. A public breach is one that is easily found on the internet, while a private breach is often exclusive to SpyCloud. | 
| SpyCloud.BreachList.title | String | Breach title. For each ingested breach our security research team documents a breach title. This is only available when we can disclose the breach details, otherwise it will have a generic title. | 
| SpyCloud.BreachList.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.BreachList.description | String | Breach description. For each ingested breach our security research team documents a breach description. This is only available when we can disclose the breach details, otherwise it will have a generic description. | 
| SpyCloud.BreachList.site_description | String | Description of the breached organization, when available. | 
| SpyCloud.BreachList.assets.phone | Number | Phone number. | 
| SpyCloud.BreachList.assets.gender | Number | Gender specifier. Typically set to 'M', 'F', 'Male', or 'Female'. | 
| SpyCloud.BreachList.assets.company_name | Number | Company name. | 
| SpyCloud.BreachList.assets.user_agent | Number | Browser agent string. | 
| SpyCloud.BreachList.assets.country | Number | Country name. | 
| SpyCloud.BreachList.assets.social_telegram | Number | Telegram username. | 
| SpyCloud.BreachList.assets.social_skype | Number | Skype username. | 
| SpyCloud.BreachList.assets.state | Number | State name. | 
| SpyCloud.BreachList.assets.account_login_time | Number | Last account login time. In ISO 8601 datetime format. | 
| SpyCloud.BreachList.assets.ip_addresses | Number | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.BreachList.assets.postal_code | Number | Postal code, usually zip code in USA. | 
| SpyCloud.BreachList.assets.dob | Number | Date of birth. In ISO 8601 datetime format. | 
| SpyCloud.BreachList.assets.account_signup_time | Number | Account signup date. In ISO 8601 datetime format. | 
| SpyCloud.BreachList.assets.homepage | Number | User's homepage URL. | 
| SpyCloud.BreachList.assets.first_name | Number | First name. | 
| SpyCloud.BreachList.assets.country_code | Number | Country code; derived from country. | 
| SpyCloud.BreachList.assets.account_modification_time | Number | Account modification date. In ISO 8601 datetime format. | 
| SpyCloud.BreachList.assets.full_name | Number | Full name. | 
| SpyCloud.BreachList.assets.address_1 | Number | Address line 1. | 
| SpyCloud.BreachList.assets.last_name | Number | Last name. | 
| SpyCloud.BreachList.assets.email | Number | Email address. | 
| SpyCloud.BreachList.assets.city | Number | City name. | 
| SpyCloud.BreachList.assets.password | Number | Account password. | 
| SpyCloud.BreachList.assets.username | Number | Username. | 

#### Command example

```!spycloud-breach-catalog-list limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "BreachList": [
            {
                "acquisition_date": "2023-04-14T00:00:00Z",
                "assets": {
                    "account_login_time": 81547,
                    "account_modification_time": 53034,
                    "account_signup_time": 93646,
                    "city": 72289,
                    "dob": 80958,
                    "email": 199284,
                    "first_name": 63233,
                    "full_name": 60764,
                    "gender": 88517,
                    "ip_addresses": 154304,
                    "language": 70246,
                    "last_name": 60895,
                    "password": 178121,
                    "salt": 88487,
                    "state": 57089,
                    "timezone": 80714,
                    "username": 103341
                },
                "confidence": 3,
                "description": "This source has been marked as sensitive due to one of the following reasons: Revealing the source may compromise an on-going investigation. The affected site is of a controversial nature but does not validate email addresses and could therefore be used to tarnish an employee's reputation.",
                "id": 43120,
                "num_records": 199705,
                "spycloud_publish_date": "2023-05-05T00:00:00Z",
                "title": "Sensitive Source",
                "type": "PUBLIC",
                "uuid": "0f9cfacd-f583-4b16-9eb6-e2b54bc51e43"
            },
            {
                "acquisition_date": "2023-05-02T00:00:00Z",
                "assets": {
                    "av_softwares": 22,
                    "country": 64688,
                    "country_code": 64331,
                    "email": 33124,
                    "infected_machine_id": 64759,
                    "infected_time": 64736,
                    "ip_addresses": 6194,
                    "password": 64759,
                    "target_url": 64759,
                    "user_hostname": 64685,
                    "user_os": 64759,
                    "user_sys_registered_owner": 64236,
                    "username": 31635
                },
                "confidence": 3,
                "description": "stealc Stealer is a Windows-targeted stealer designed to grab form data such as IP addresses, browsing history, saved passwords, cryptocurrency, private messages and/or screenshots from affected users.",
                "id": 43491,
                "num_records": 64759,
                "premium_flag": "YES",
                "site": "n/a",
                "site_description": "stealc Stealer is a Windows-targeted stealer designed to grab form data such as IP addresses, browsing history, saved passwords, cryptocurrency, private messages and/or screenshots from affected users.",
                "spycloud_publish_date": "2023-05-05T00:00:00Z",
                "title": "stealc Stealer",
                "type": "PRIVATE",
                "uuid": "16689989-fe33-49ec-b02f-0442963ef0b7"
            }
        ]
    }
}
```

#### Human Readable Output

>### Breach List

>|Title|SpyCloud Publish Date|Description|Confidence|ID|Acquisition Date|UUID|Type|
>|---|---|---|---|---|---|---|---|
>| Sensitive Source | 2023-05-05T00:00:00Z | This source has been marked as sensitive due to one of the following reasons: Revealing the source may compromise an on-going investigation. The affected site is of a controversial nature but does not validate email addresses and could therefore be used to tarnish an employee's reputation. | 3 | 43120 | 2023-04-14T00:00:00Z | 0f9cfacd-f583-4b16-9eb6-e2b54bc51e43 | PUBLIC |
>| stealc Stealer | 2023-05-05T00:00:00Z | stealc Stealer is a Windows-targeted stealer designed to grab form data such as IP addresses, browsing history, saved passwords, cryptocurrency, private messages and/or screenshots from affected users. | 3 | 43491 | 2023-05-02T00:00:00Z | 16689989-fe33-49ec-b02f-0442963ef0b7 | PRIVATE |


### spycloud-breach-catalog-get

***
Get Breach Catalog Information by ID.

#### Base Command

`spycloud-breach-catalog-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Numerical ID of the breach. Both integer and UUIDv4 ID formats are supported. You may also use a comma delimiter to request more than one breach at a time. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.BreachData.site | String | Website of breached organization, when available. | 
| SpyCloud.BreachData.confidence | Number | Numerical score representing the confidence in the source of the breach. | 
| SpyCloud.BreachData.id | Number | Numerical breach ID. This number correlates to source_id data point found in breach records. | 
| SpyCloud.BreachData.acquisition_date | Date | The date on which our security research team first acquired the breached data. | 
| SpyCloud.BreachData.uuid | String | UUID v4 encoded version of breach ID. This is relevant for users of Firehose, where each deliverable \(records file\) is named using the breach UUID. | 
| SpyCloud.BreachData.num_records | Number | Number of records we parsed and ingested from this particular breach. This is after parsing, normalization and deduplication take place. | 
| SpyCloud.BreachData.type | String | Denotes if a breach is considered public or private. A public breach is one that is easily found on the internet, while a private breach is often exclusive to SpyCloud. | 
| SpyCloud.BreachData.title | String | Breach title. For each ingested breach our security research team documents a breach title. This is only available when we can disclose the breach details, otherwise it will have a generic title. | 
| SpyCloud.BreachData.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.BreachData.description | String | Breach description. For each ingested breach our security research team documents a breach description. This is only available when we can disclose the breach details, otherwise it will have a generic description. | 
| SpyCloud.BreachData.site_description | String | Description of the breached organization, when available. | 
| SpyCloud.BreachData.assets.phone | Number | Phone number. | 
| SpyCloud.BreachData.assets.gender | Number | Gender specifier. Typically set to 'M', 'F', 'Male', or 'Female'. | 
| SpyCloud.BreachData.assets.company_name | Number | Company name. | 
| SpyCloud.BreachData.assets.user_agent | Number | Browser agent string. | 
| SpyCloud.BreachData.assets.country | Number | Country name. | 
| SpyCloud.BreachData.assets.social_telegram | Number | Telegram username. | 
| SpyCloud.BreachData.assets.social_skype | Number | Skype username. | 
| SpyCloud.BreachData.assets.state | Number | State name. | 
| SpyCloud.BreachData.assets.account_login_time | Number | Last account login time. In ISO 8601 datetime format. | 
| SpyCloud.BreachData.assets.ip_addresses | Number | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.BreachData.assets.postal_code | Number | Postal code, usually zip code in USA. | 
| SpyCloud.BreachData.assets.dob | Number | Date of birth. In ISO 8601 datetime format. | 
| SpyCloud.BreachData.assets.account_signup_time | Number | Account signup date. In ISO 8601 datetime format. | 
| SpyCloud.BreachData.assets.homepage | Number | User's homepage URL. | 
| SpyCloud.BreachData.assets.first_name | Number | First name. | 
| SpyCloud.BreachData.assets.country_code | Number | Country code; derived from country. | 
| SpyCloud.BreachData.assets.account_modification_time | Number | Account modification date. In ISO 8601 datetime format. | 
| SpyCloud.BreachData.assets.full_name | Number | Full name. | 
| SpyCloud.BreachData.assets.address_1 | Number | Address line 1. | 
| SpyCloud.BreachData.assets.last_name | Number | Last name. | 
| SpyCloud.BreachData.assets.email | Number | Email address. | 
| SpyCloud.BreachData.assets.city | Number | City name. | 
| SpyCloud.BreachData.assets.password | Number | Account password. | 
| SpyCloud.BreachData.assets.username | Number | Username. | 

#### Command example

```!spycloud-breach-catalog-get id=39897 limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "BreachData": {
            "acquisition_date": "2022-10-04T00:00:00Z",
            "assets": {
                "address_1": 22037,
                "city": 22037,
                "dob": 56967,
                "email": 61479,
                "first_name": 62366,
                "full_name": 62366,
                "gender": 22041,
                "job_title": 4642,
                "last_name": 62366,
                "middle_name": 13430,
                "phone": 25997,
                "postal_code": 22037,
                "state": 22037
            },
            "confidence": 3,
            "description": "On an unknown date, data allegedly belonging to Mansfield Independent School District, a U.S-based educational district, was leaked online. The data contains names, email addresses, phone numbers, addresses and additional personal information. This leak is being publicly shared on online forums.",
            "id": 39897,
            "num_records": 62366,
            "site": "mansfieldisd.org",
            "site_description": "Mansfield Independent School District is an educational district based in the U.S.",
            "spycloud_publish_date": "2023-04-18T00:00:00Z",
            "title": "Mansfield Independent School District",
            "type": "PUBLIC",
            "uuid": "c504f30a-6fe7-48df-becf-4e14f16e6c0d"
        }
    }
}
```

#### Human Readable Output

>### Breach data for id 39897

>|Title|SpyCloud Publish Date|Description|Confidence|ID|Acquisition Date|UUID|Type|
>|---|---|---|---|---|---|---|---|
>| Mansfield Independent School District | 2023-04-18T00:00:00Z | On an unknown date, data allegedly belonging to Mansfield Independent School District, a U.S-based educational district, was leaked online. The data contains names, email addresses, phone numbers, addresses and additional personal information. This leak is being publicly shared on online forums. | 3 | 39897 | 2022-10-04T00:00:00Z | c504f30a-6fe7-48df-becf-4e14f16e6c0d | PUBLIC |


### spycloud-domain-data-get

***
Get Breach Data by Domain.

#### Base Command

`spycloud-domain-data-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain or Subdomain name to search for. | Required | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. | Optional | 
| type | This parameter lets you filter results by several types. The allowed values are 'corporate' for corporate records, and 'infected' for infected user records, email_domain to just match against email domains, and target_domain to just match against target domains or subdomains. If no value has been provided the API function will, by default, return all record types. Possible values are: corporate, infected, , email_domain, target_domain. | Optional | 
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. Example:-  YYYY-MM-DD. | Optional | 
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field.<br/> Example:-  YYYY-MM-DD. | Optional | 
| severity | This parameter allows you to filter based on the numeric severity code.<br/>Possible values are:<br/>2 -&gt; Email only severity. This record is part of an email-only list.<br/>5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all.<br/>20 -&gt;High severity. This severity value is given to breach records where we have an email address and a plaintext password.<br/>25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine (botnet data). These records will always have a plaintext password and most will have an email address. Possible values are: . | Optional | 
| source_id | This parameter allows you to filter based on a particular breach source. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| all_results | Fetch all results. Possible values are: True, False. | Optional | 
| since_modification_date | This parameter allows you to define the starting point for a date range query on when an already published record was modified (record_modification_date). | Optional | 
| until_modification_date | This parameter allows you to define the ending point for a date range query on the when an already published record was modified (record_modification_date). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.Domain.username | String | Username. | 
| SpyCloud.Domain.password | String | Account password. | 
| SpyCloud.Domain.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.Domain.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.Domain.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.Domain.user_browser | String | Browser name. | 
| SpyCloud.Domain.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.Domain.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.Domain.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.Domain.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.Domain.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.Domain.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.Domain.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.Domain.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.Domain.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.Domain.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.Domain.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.Domain.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.Domain.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.Domain.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.Domain.email | String | Email address. | 
| SpyCloud.Domain.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.Domain.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.Domain.domain | String | Domain name. | 

#### Command example

```!spycloud-domain-data-get domain=dummy.com limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "Domain": [
            {
                "company_name": "dummy",
                "document_id": "0046c7e3-fcf4-4d24-9c45-255116054640",
                "domain": "dummy.com",
                "email": "Dummy Email",
                "email_domain": "dummy.com",
                "email_username": "smoolagiri",
                "first_name": "Shyam",
                "full_name": "Shyam Moolagiri",
                "job_title": "Senior Team Lead Qa",
                "last_name": "Moolagiri",
                "phone": "7039567410",
                "severity": 5,
                "source_id": 41180,
                "spycloud_publish_date": "2023-03-28T00:00:00Z"
            },
            {
                "city": "Chantilly",
                "company_name": "dummy",
                "document_id": "0fa88054-5d74-412a-bc40-0935a6d6e2d5",
                "domain": "dummy.com",
                "email": "dummy Email",
                "email_domain": "dummy.com",
                "email_username": "srobert",
                "first_name": "Sam",
                "full_name": "Sam Robert",
                "job_title": "Lead Recruiting Specialist",
                "last_name": "Robert",
                "phone": "7039567410",
                "severity": 5,
                "social_linkedin": [
                    "sam-robert-37746b35"
                ],
                "source_id": 41180,
                "spycloud_publish_date": "2023-03-28T00:00:00Z",
                "state": "VA"
            }
        ]
    }
}
```

#### Human Readable Output

>### Breach List for domain dummy.com

>|Source ID| Email       |Full Name|Email Domain|Email Username|SpyCloud Publish Date|Domain|Document ID|Severity|
>|---|-------------|---|---|---|---|---|---|---|
>| 41180 | Dummy Email | Shyam Moolagiri | dummy.com | smoolagiri | <br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/>2023-03-28T00:00:00Z | dummy.com | 0046c7e3-fcf4-4d24-9c45-255116054640 | 5 |
>| 41180 | Dummy Email | Sam Robert | dummy.com | srobert | <br/><br/><br/><br/><br/><br/><br/><br/><br/><br/>2023-03-28T00:00:00Z | <br/>dummy.com | 0fa88054-5d74-412a-bc40-0935a6d6e2d5 | 5 |


### spycloud-username-data-get

***
Get Breach Data by Username.

#### Base Command

`spycloud-username-data-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. | Optional | 
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field. | Optional | 
| since_modification_date | This parameter allows you to define the starting point for a date range query on when an already published record was modified (record_modification_date). | Optional | 
| until_modification_date | This parameter allows you to define the ending point for a date range<br/> query on the when an already published record was modified (record_modification_date). | Optional | 
| severity | This parameter allows you to filter based on the numeric severity code.<br/>Possible values are:<br/>2 -&gt; Email only severity. This record is part of an email-only list.<br/>5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all.<br/>20 -&gt;High severity. This severity value is given to breach records where we have an email address and a plaintext password.<br/>25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine (botnet data). These records will always have a plaintext password and most will have an email address. Possible values are: . | Optional | 
| source_id | This parameter allows you to filter based on a particular breach source. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. | Optional | 
| username | Username you wish to search for. | Required | 
| all_results | Fetch all results. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.Username.username | String | Username. | 
| SpyCloud.Username.password | String | Account password. | 
| SpyCloud.Username.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.Username.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.Username.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.Username.user_browser | String | Browser name. | 
| SpyCloud.Username.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.Username.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.Username.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.Username.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.Username.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.Username.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.Username.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.Username.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.Username.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.Username.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.Username.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.Username.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.Username.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.Username.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.Username.email | String | Email address. | 
| SpyCloud.Username.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.Username.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.Username.domain | String | Domain name. | 

#### Command example

```!spycloud-username-data-get username=abc limit=2```

#### Human Readable Output

>No data to present.


### spycloud-ip-address-data-get

***
Get Breach Data by IP Address.

#### Base Command

`spycloud-ip-address-data-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. | Optional | 
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field. | Optional | 
| since_modification_date | This parameter allows you to define the starting point for a date range query on when an already published record was modified (record_modification_date). | Optional | 
| until_modification_date | This parameter allows you to define the ending point for a date range<br/> query on the when an already published record was modified (record_modification_date). | Optional | 
| severity | This parameter allows you to filter based on the numeric severity code.<br/>Possible values are:<br/>2 -&gt; Email only severity. This record is part of an email-only list.<br/>5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all.<br/>20 -&gt;High severity. This severity value is given to breach records where we have an email address and a plaintext password.<br/>25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine (botnet data). These records will always have a plaintext password and most will have an email address. Possible values are: . | Optional | 
| source_id | This parameter allows you to filter based on a particular breach source. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. | Optional | 
| ip | IP address or network CIDR notation to search for. For CIDR notation, use an underscore instead of a slash. | Required | 
| all_results | Fecth all results. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.IPAddress.username | String | Username. | 
| SpyCloud.IPAddress.password | String | Account password. | 
| SpyCloud.IPAddress.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.IPAddress.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.IPAddress.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.IPAddress.user_browser | String | Browser name. | 
| SpyCloud.IPAddress.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.IPAddress.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.IPAddress.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.IPAddress.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.IPAddress.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.IPAddress.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.IPAddress.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.IPAddress.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.IPAddress.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.IPAddress.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.IPAddress.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.IPAddress.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.IPAddress.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.IPAddress.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.IPAddress.email | String | Email address. | 
| SpyCloud.IPAddress.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.IPAddress.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.IPAddress.domain | String | Domain name. | 

#### Command example

```!spycloud-ip-address-data-get ip=4.4.4.4 limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "IPAddress": [
            {
                "account_last_activity_time": "2020-09-20T16:56:05Z",
                "account_signup_time": "2020-09-20T16:56:05Z",
                "country": "INDIA",
                "country_code": "IN",
                "document_id": "44a59857-49dd-445b-8d19-c9ddc12ecde5",
                "domain": "gmail.com",
                "email": "Dummy Email",
                "email_domain": "gmail.com",
                "email_username": "bossmsrao",
                "ip_addresses": [
                    "4.4.4.4"
                ],
                "severity": 5,
                "source_id": 38326,
                "spycloud_publish_date": "2021-12-02T00:00:00Z",
                "username": "bossssomesh"
            },
            {
                "account_login_time": "2018-04-09T09:56:39Z",
                "account_modification_time": "2018-04-09T09:57:44Z",
                "account_signup_time": "2018-04-09T09:56:39Z",
                "document_id": "cb71703c-9447-421f-b53a-6a1e3508eadc",
                "domain": "dummy.com",
                "email": "Dummy Email",
                "email_domain": "dummy.com",
                "email_username": "sghouse",
                "full_name": "Ghouse",
                "ip_addresses": [
                    "4.4.4.4"
                ],
                "password": "********",
                "password_type": "bcrypt",
                "severity": 5,
                "sighting": 1,
                "source_id": 16670,
                "spycloud_publish_date": "2021-05-05T00:00:00Z",
                "timezone": "La Paz",
                "username": "ghouse260"
            }
        ]
    }
}
```

#### Human Readable Output

>### Breach List for IP address 

>|Source ID| Email           |Full Name|User Name|Email Domain|Email Username|Password|Password Type|IP Addresses|SpyCloud Publish Date|Domain|Document ID|Severity|Sighting|
>|---|-----------------|---|---|---|---|---|---|---|---|---|---|---|---|
>| 38326 | Dummy Email |  | bossssomesh | gmail.com | bossmsrao |  |  | 4.4.4.4 | 2021-12-02T00:00:00Z | gmail.com | 44a59857-49dd-445b-8d19-c9ddc12ecde5 | 5 |  |
>| 16670 | Dummy Email | Ghouse | ghouse260 | dummy.com | sghouse | ******** | bcrypt | 4.4.4.4 | 2021-05-05T00:00:00Z | dummy.com | cb71703c-9447-421f-b53a-6a1e3508eadc | 5 | 1 |


### spycloud-email-data-get

***
Get Breach Data by Email.

#### Base Command

`spycloud-email-data-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. | Optional | 
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field. | Optional | 
| since_modification_date | This parameter allows you to define the starting point for a date range query on when an already published record was modified (record_modification_date). | Optional | 
| until_modification_date | This parameter allows you to define the ending point for a date range<br/> query on the when an already published record was modified (record_modification_date). | Optional | 
| severity | This parameter allows you to filter based on the numeric severity code.<br/>Possible values are:<br/>2 -&gt; Email only severity. This record is part of an email-only list.<br/>5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all.<br/>20 -&gt;High severity. This severity value is given to breach records where we have an email address and a plaintext password.<br/>25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine (botnet data). These records will always have a plaintext password and most will have an email address. Possible values are: . | Optional | 
| source_id | This parameter allows you to filter based on a particular breach source. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. | Optional | 
| email | Email address to search for. | Required | 
| all_results | Fetch all results. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.EmailAddress.username | String | Username. | 
| SpyCloud.EmailAddress.password | String | Account password. | 
| SpyCloud.EmailAddress.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.EmailAddress.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.EmailAddress.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.EmailAddress.user_browser | String | Browser name. | 
| SpyCloud.EmailAddress.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.EmailAddress.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.EmailAddress.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.EmailAddress.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.EmailAddress.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.EmailAddress.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.EmailAddress.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.EmailAddress.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.EmailAddress.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.EmailAddress.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.EmailAddress.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.EmailAddress.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.EmailAddress.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.EmailAddress.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.EmailAddress.email | String | Email address. | 
| SpyCloud.EmailAddress.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.EmailAddress.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.EmailAddress.domain | String | Domain name. | 

#### Command example

```!spycloud-email-data-get email=Dummmy Email limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "EmailAddress": {
            "company_name": "dummy",
            "document_id": "0046c7e3-fcf4-4d24-9c45-255116054640",
            "domain": "dummy.com",
            "email": "Dummy Email",
            "email_domain": "dummy.com",
            "email_username": "smoolagiri",
            "first_name": "Shyam",
            "full_name": "Shyam Moolagiri",
            "job_title": "Senior Team Lead Qa",
            "last_name": "Moolagiri",
            "phone": "7039567410",
            "severity": 5,
            "source_id": 41180,
            "spycloud_publish_date": "2023-03-28T00:00:00Z"
        }
    }
}
```

#### Human Readable Output

>### Breach List for Email address Dummy Email

>|Source ID| Email       |Full Name|Email Domain|Email Username|SpyCloud Publish Date|Domain|Document ID|Severity|
>|---|-------------|---|---|---|---|---|---|---|
>| 41180 | Dummy Email | Shyam Moolagiri | dummy.com | smoolagiri | 2023-03-28T00:00:00Z | dummy.com   | 0046c7e3-fcf4-4d24-9c45-255116054640 | 5 |


### spycloud-password-data-get

***
Get Breach Data by Password.

#### Base Command

`spycloud-password-data-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. | Optional | 
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field. | Optional | 
| since_modification_date | This parameter allows you to define the starting point for a date range query on when an already published record was modified (record_modification_date). | Optional | 
| until_modification_date | This parameter allows you to define the ending point for a date range<br/> query on the when an already published record was modified (record_modification_date). | Optional | 
| severity | This parameter allows you to filter based on the numeric severity code.<br/>Possible values are:<br/>2 -&gt; Email only severity. This record is part of an email-only list.<br/>5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all.<br/>20 -&gt;High severity. This severity value is given to breach records where we have an email address and a plaintext password.<br/>25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine (botnet data). These records will always have a plaintext password and most will have an email address. Possible values are: . | Optional | 
| source_id | This parameter allows you to filter based on a particular breach source. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. | Optional | 
| password | Password you wish to search for. | Required | 
| all_results | Fetch all results. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.Password.username | String | Username. | 
| SpyCloud.Password.password | String | Account password. | 
| SpyCloud.Password.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.Password.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.Password.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.Password.user_browser | String | Browser name. | 
| SpyCloud.Password.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.Password.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.Password.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.Password.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.Password.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.Password.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.Password.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.Password.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.Password.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.Password.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.Password.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.Password.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.Password.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.Password.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.Password.email | String | Email address. | 
| SpyCloud.Password.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.Password.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.Password.domain | String | Domain name. | 

#### Command example

```!spycloud-password-data-get password=welcome@123 limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "Password": {
            "country": "INDIA",
            "country_code": "IN",
            "document_id": "bc436d97-395c-4b03-819b-9b8fad7711bd",
            "domain": "dummy.com",
            "email": "Dummy Email",
            "email_domain": "dummy.com",
            "email_username": "kummadisetti",
            "infected_machine_id": "51aa3c3d-090e-417a-8e8c-3a94726e5fed",
            "ip_addresses": [
                "4.4.4.4"
            ],
            "password": "welcome@123",
            "password_plaintext": "welcome@123",
            "password_type": "plaintext",
            "record_modification_date": "2022-05-13T00:00:00Z",
            "severity": 25,
            "sighting": 1,
            "source_id": 37732,
            "spycloud_publish_date": "2021-06-24T00:00:00Z",
            "target_domain": "slack.com",
            "target_subdomain": "dummy.slack.com",
            "target_url": "dummy.slack.com",
            "user_sys_registered_owner": "saket"
        }
    }
}
```

#### Human Readable Output

>### Breach List for Password welcome@123

>|Source ID|Email|Email Domain|Email Username|Target Domain|Target Subdomain|Password|Password Plaintext|Password Type|Target URL|IP Addresses|Infected Machine ID|User SYS Registered Owner|SpyCloud Publish Date|Domain|Document ID|Severity|Sighting|
>|---|--|---|---|---|---|---|---|---|---|--|---|---|---|---|---|---|---|
>| 37732 | Dummy Email | dummy.com | kummadisetti | slack.com | dummy.slack.com | welcome@123 | welcome@123 | plaintext | dummy.slack.com | 4.4.4.4 | 51aa3c3d-090e-417a-8e8c-3a94726e5fed | saket | 2021-06-24T00:00:00Z | dummy.com | bc436d97-395c-4b03-819b-9b8fad7711bd | 25 | 1 |


### spycloud-watchlist-data-list

***
List Breach Data. By default, this lists all breach data for the customer's configured watchlist. With the arguments, it's possible to scope the results.

#### Base Command

`spycloud-watchlist-data-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. | Optional | 
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field. | Optional | 
| since_modification_date | This parameter allows you to define the starting point for a date range query on when an already published record was modified (record_modification_date). | Optional | 
| until_modification_date | This parameter allows you to define the ending point for a date range<br/> query on the when an already published record was modified (record_modification_date). | Optional | 
| severity | This parameter allows you to filter based on the numeric severity code.<br/>Possible values are:<br/>2 -&gt; Email only severity. This record is part of an email-only list.<br/>5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all.<br/>20 -&gt;High severity. This severity value is given to breach records where we have an email address and a plaintext password.<br/>25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine (botnet data). These records will always have a plaintext password and most will have an email address. Possible values are: . | Optional | 
| source_id | This parameter allows you to filter based on a particular breach source. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. | Optional | 
| type | This parameter lets you filter results by type. The allowed values are 'corporate' for corporate records, and 'infected' for infected user records (from botnet data). If no value has been provided the API function will, by default, return all record types. Possible values are: corporate, infected. | Optional | 
| watchlist_type | This parameters lets you filter results for only emails or only domains on your watchlist. If no value has been provided, the API will return all watchlist types. Possible values are: email, domain, subdomain, ip. | Optional | 
| all_results | Fetch all results. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.Watchlist.username | String | Username. | 
| SpyCloud.Watchlist.password | String | Account password. | 
| SpyCloud.Watchlist.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.Watchlist.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.Watchlist.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.Watchlist.user_browser | String | Browser name. | 
| SpyCloud.Watchlist.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.Watchlist.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.Watchlist.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.Watchlist.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.Watchlist.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.Watchlist.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.Watchlist.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.Watchlist.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.Watchlist.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.Watchlist.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.Watchlist.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.Watchlist.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.Watchlist.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.Watchlist.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.Watchlist.email | String | Email address. | 
| SpyCloud.Watchlist.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.Watchlist.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.Watchlist.domain | String | Domain name. | 

#### Command example

```!spycloud-watchlist-data-list limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "Watchlist": [
            {
                "company_name": "dummy",
                "document_id": "0046c7e3-fcf4-4d24-9c45-255116054640",
                "domain": "dummy.com",
                "email": "Dummy Email",
                "email_domain": "dummy.com",
                "email_username": "smoolagiri",
                "first_name": "Shyam",
                "full_name": "Shyam Moolagiri",
                "job_title": "Senior Team Lead Qa",
                "last_name": "Moolagiri",
                "phone": "7039567410",
                "severity": 5,
                "source_id": 41180,
                "spycloud_publish_date": "2023-03-28T00:00:00Z"
            },
            {
                "city": "Chantilly",
                "company_name": "dummy",
                "document_id": "0fa88054-5d74-412a-bc40-0935a6d6e2d5",
                "domain": "dummy.com",
                "email": "Dummy Email",
                "email_domain": "dummy.com",
                "email_username": "srobert",
                "first_name": "Sam",
                "full_name": "Sam Robert",
                "job_title": "Lead Recruiting Specialist",
                "last_name": "Robert",
                "phone": "7039567410",
                "severity": 5,
                "social_linkedin": [
                    "sam-robert-37746b35"
                ],
                "source_id": 41180,
                "spycloud_publish_date": "2023-03-28T00:00:00Z",
                "state": "VA"
            }
        ]
    }
}
```

#### Human Readable Output

>### Watchlist Data

>|Source ID|Email|Full Name|Email Domain|Email Username|SpyCloud Publish Date|Domain|Document ID|Severity|
>|---|--|---|---|---|---|---|---|---|
>| 41180 | Dummy Email | Shyam Moolagiri | dummy.com | smoolagiri | 2023-03-28T00:00:00Z | dummy.com | 0046c7e3-fcf4-4d24-9c45-255116054640 | 5 |
>| 41180 | Dummy Email | Sam Robert | dummy.com | srobert | 2023-03-28T00:00:00Z | dummy.com | 0fa88054-5d74-412a-bc40-0935a6d6e2d5 | 5 |


### spycloud-compass-device-data-get

***
Get Compass device data by infected_machine_id.

#### Base Command

`spycloud-compass-device-data-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| infected_machine_id | One or more comma delimited Infected Machine ID to search for compass breach records. | Required | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.CompassDeviceData.username | String | Username. | 
| SpyCloud.CompassDeviceData.password | String | Account password. | 
| SpyCloud.CompassDeviceData.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.CompassDeviceData.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.CompassDeviceData.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.CompassDeviceData.user_browser | String | Browser name. | 
| SpyCloud.CompassDeviceData.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.CompassDeviceData.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.CompassDeviceData.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.CompassDeviceData.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.CompassDeviceData.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.CompassDeviceData.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.CompassDeviceData.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.CompassDeviceData.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.CompassDeviceData.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.CompassDeviceData.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.CompassDeviceData.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.CompassDeviceData.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.CompassDeviceData.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.CompassDeviceData.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.CompassDeviceData.email | String | Email address. | 
| SpyCloud.CompassDeviceData.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.CompassDeviceData.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.CompassDeviceData.domain | String | Domain name. | 

#### Command example

```!spycloud-compass-device-data-get infected_machine_id=72aaaec1-afa1-4d9e-838f-abfcbbf3ff82 limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "CompassDeviceData": {
            "display_resolution": "1280x720",
            "document_id": "c8a11837-808a-4b1e-b9d8-cfba0739c7f5",
            "infected_machine_id": "72aaaec1-afa1-4d9e-838f-abfcbbf3ff82",
            "ip_addresses": [
                "4.4.4.4"
            ],
            "password": "Tron99***018",
            "password_plaintext": "Tron99***018",
            "password_type": "plaintext",
            "severity": 25,
            "source_id": 41985,
            "spycloud_publish_date": "2023-03-02T00:00:00Z",
            "target_domain": "greythr.com",
            "target_subdomain": "dummy.greythr.com",
            "target_url": "dummy.greythr.com",
            "user_browser": "Chrome (v109.0.5414.120-64, Profile: Profile 1)",
            "user_os": "Windows 10 Pro",
            "username": "345"
        }
    }
}
```

#### Human Readable Output

>### Compass Devices - Data

>|Source ID|User Name|Target Domain|Target Subdomain|Password|Password Plaintext|Password Type|Target URL|User Browser|IP Addresses|Infected Machine ID|User OS|SpyCloud Publish Date|Document ID|Severity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 41985 | 345 | greythr.com | dummy.greythr.com | Tron99***018 | Tron99***018 | plaintext | dummy.greythr.com | Chrome (v109.0.5414.120-64, Profile: Profile 1) | 4.4.4.4 | 72aaaec1-afa1-4d9e-838f-abfcbbf3ff82 | Windows 10 Pro | 2023-03-02T00:00:00Z | c8a11837-808a-4b1e-b9d8-cfba0739c7f5 | 25 |


### spycloud-compass-data-list

***
List Compass data. By default, this lists all Compass data. With the arguments, it's possible to scope the results.

#### Base Command

`spycloud-compass-data-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | This parameter allows you to define the starting point for a date<br/>        range query on the spycloud_publish_date field. | Optional | 
| until | This parameter allows you to define the ending point for a date<br/>        range query on the spycloud_publish_date field. | Optional | 
| since_infected | This parameter allows you to define the starting point for a date range query on the infected_time field. | Optional | 
| until_infected | This parameter allows you to define the ending point for a date range query on the infected_time field. | Optional | 
| source_id | This parameter allows you to filter based on a particular breach source. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| limit | The maximum number of records to return from the collection. Limit<br/>        default value is 50. | Optional | 
| type | This parameter will return records that are verified or unverified, meaning those that matched the watchlist or not. By default if type is not used, both types will be returned. Possible values are: verified, unverified. | Optional | 
| all_results | Fetch all results. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.CompassDataList.username | String | Username. | 
| SpyCloud.CompassDataList.password | String | Account password. | 
| SpyCloud.CompassDataList.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.CompassDataList.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.CompassDataList.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.CompassDataList.user_browser | String | Browser name. | 
| SpyCloud.CompassDataList.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.CompassDataList.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.CompassDataList.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.CompassDataList.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.CompassDataList.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.CompassDataList.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.CompassDataList.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.CompassDataList.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.CompassDataList.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.CompassDataList.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.CompassDataList.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.CompassDataList.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.CompassDataList.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.CompassDataList.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.CompassDataList.email | String | Email address. | 
| SpyCloud.CompassDataList.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.CompassDataList.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.CompassDataList.domain | String | Domain name. | 

#### Command example

```!spycloud-compass-data-list limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "CompassDataList": [
            {
                "display_resolution": "1280x720",
                "document_id": "c8a11837-808a-4b1e-b9d8-cfba0739c7f5",
                "infected_machine_id": "72aaaec1-afa1-4d9e-838f-abfcbbf3ff82",
                "ip_addresses": [
                    "4.4.4.4"
                ],
                "password": "Tron99***018",
                "password_plaintext": "Tron99***018",
                "password_type": "plaintext",
                "severity": 25,
                "source_id": 41985,
                "spycloud_publish_date": "2023-03-02T00:00:00Z",
                "target_domain": "greythr.com",
                "target_subdomain": "dummy.greythr.com",
                "target_url": "dummy.greythr.com",
                "user_browser": "Chrome (v109.0.5414.120-64, Profile: Profile 1)",
                "user_os": "Windows 10 Pro",
                "username": "345"
            },
            {
                "document_id": "89ed3bb4-b523-4037-9f1b-be49e99ce59f",
                "domain": "gmail.com",
                "email": "Dummy Email",
                "email_domain": "gmail.com",
                "email_username": "var*****2",
                "infected_machine_id": "eb36d8f4-b802-416a-9e94-cdb419782b10",
                "infected_path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe",
                "infected_time": "2022-12-29T11:01:47Z",
                "ip_addresses": [
                    "4.4.4.4"
                ],
                "keyboard_languages": "english (india) / english (united states)",
                "password": "********",
                "password_plaintext": "********",
                "password_type": "plaintext",
                "severity": 25,
                "source_id": 40883,
                "spycloud_publish_date": "2023-01-06T00:00:00Z",
                "target_domain": "amazon.com",
                "target_subdomain": "signin.aws.amazon.com",
                "target_url": "signin.aws.amazon.com",
                "user_browser": "Mozilla Firefox",
                "user_hostname": "LAPPY",
                "user_os": "Windows 10 Pro [x64]",
                "user_sys_registered_owner": "Home"
            }
        ]
    }
}
```

#### Human Readable Output

>### Compass Data List

>|Source ID| Email         |User Name|Email Domain|Email Username|Target Domain|Target Subdomain|Password|Password Plaintext|Password Type|Target URL|User Browser|IP Addresses|Infected Machine ID|Infected Path|Infected Time|User Hostname|User OS|User SYS Registered Owner|SpyCloud Publish Date|Domain|Document ID|Severity|
>|---|---------------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 41985 |               | 345 |  |  | greythr.com | dummy.greythr.com | Tron99***018 | Tron99***018 | plaintext | dummy.greythr.com | Chrome (v109.0.5414.120-64, Profile: Profile 1) | 4.4.4.4 | 72aaaec1-afa1-4d9e-838f-abfcbbf3ff82 |  |  |  | Windows 10 Pro |  | 2023-03-02T00:00:00Z |  | c8a11837-808a-4b1e-b9d8-cfba0739c7f5 | 25 |
>| 40883 | Dummy Email |  | gmail.com | var*****2 | amazon.com | signin.<br/><br/><br/>aws.<br/><br/>amazon.com | ******** | ******** | plaintext | signin.aws.amazon.com | Mozilla Firefox | 4.4.4.4 | eb36d8f4-b802-416a-9e94-cdb419782b10 | C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe | 2022-12-29T11:01:47Z | LAPPY | Windows 10 Pro [x64] | Home | 2023-01-06T00:00:00Z | gmail.com | 89ed3bb4-b523-4037-9f1b-be49e99ce59f | 25 |


### spycloud-compass-device-list

***
List Compass device data. By default, this lists all devices. With the arguments, it's possible to scope the results.

#### Base Command

`spycloud-compass-device-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_id | This parameter allows you to filter based on a particular breach source. | Optional | 
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. | Optional | 
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field. | Optional | 
| since_infected | This parameter allows you to define the starting point for a date range query on the infected_time. | Optional | 
| until_infected | This parameter allows you to define the ending point for a date range query on the infected_time field. | Optional | 
| limit | The maximum number of records to return from the collection. Limit<br/>        default value is 50. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.CompassDeviceList.username | String | Username. | 
| SpyCloud.CompassDeviceList.password | String | Account password. | 
| SpyCloud.CompassDeviceList.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.CompassDeviceList.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.CompassDeviceList.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.CompassDeviceList.user_browser | String | Browser name. | 
| SpyCloud.CompassDeviceList.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.CompassDeviceList.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.CompassDeviceList.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.CompassDeviceList.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.CompassDeviceList.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.CompassDeviceList.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.CompassDeviceList.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.CompassDeviceList.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.CompassDeviceList.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.CompassDeviceList.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.CompassDeviceList.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.CompassDeviceList.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.CompassDeviceList.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.CompassDeviceList.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.CompassDeviceList.email | String | Email address. | 
| SpyCloud.CompassDeviceList.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.CompassDeviceList.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.CompassDeviceList.domain | String | Domain name. | 

#### Command example

```!spycloud-compass-device-list limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "CompassDeviceList": [
            {
                "application_count": 1,
                "infected_machine_id": "72aaaec1-afa1-4d9e-838f-abfcbbf3ff82",
                "ip_addresses": [
                    "4.4.4.4"
                ],
                "source_id": 41985,
                "spycloud_publish_date": "2023-03-02T00:00:00Z",
                "user_os": "Windows 10 Pro"
            },
            {
                "application_count": 29,
                "infected_machine_id": "eb36d8f4-b802-416a-9e94-cdb419782b10",
                "infected_time": "2022-12-29T11:01:47Z",
                "ip_addresses": [
                    "4.4.4.4"
                ],
                "source_id": 40883,
                "spycloud_publish_date": "2023-01-06T00:00:00Z",
                "user_hostname": "LAPPY",
                "user_os": "Windows 10 Pro [x64]"
            }
        ]
    }
}
```

#### Human Readable Output

>### Compass Device List

>|Source ID|IP Addresses|Infected Machine ID|Infected Time|User Hostname|User OS|SpyCloud Publish Date|
>|---|---|---|---|---|---|---|
>| 41985 | 4.4.4.4 | 72aaaec1-afa1-4d9e-838f-abfcbbf3ff82 |  |  | Windows 10 Pro | 2023-03-02T00:00:00Z |
>| 40883 | 4.4.4.4 | eb36d8f4-b802-416a-9e94-cdb419782b10 | 2022-12-29T11:01:47Z | LAPPY | Windows 10 Pro [x64] | 2023-01-06T00:00:00Z |


### spycloud-compass-application-data-get

***
Get Compass application data for a specific application.

#### Base Command

`spycloud-compass-application-data-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_application | One or more comma delimited Compass target application (subdomain or domain) to search for. | Required | 
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. | Optional | 
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field. | Optional | 
| source_id | This parameter allows you to filter based on a particular breach source. | Optional | 
| limit | The maximum number of records to return from the collection. Limit<br/>        default value is 50. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.CompassApplicationData.username | String | Username. | 
| SpyCloud.CompassApplicationData.password | String | Account password. | 
| SpyCloud.CompassApplicationData.password_plaintext | String | The cracked, plaintext version of the password \(where the password is crackable\). | 
| SpyCloud.CompassApplicationData.password_type | String | Password type for original password as found in the data breach. This will either be plaintext or one of the many password hash/encryption types \(SHA1, MD5, 3DES, etc\). | 
| SpyCloud.CompassApplicationData.target_url | String | URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system. | 
| SpyCloud.CompassApplicationData.user_browser | String | Browser name. | 
| SpyCloud.CompassApplicationData.ip_addresses | String | List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported. | 
| SpyCloud.CompassApplicationData.infected_machine_id | String | A unique identifier either extracted from an infostealer log, when present, or an RFC 4122-compliant universally unique identifier \(UUID\) generated by SpyCloud, when no identifier is present in an infected record. The method of generation of these identifiers varies by malware family and may or may not conform to a UUID format. For the ID's in the aforementioned UUID format, there is not currently any way to determine whether an infected_machine_id was extracted from a malware log or generated by SpyCloud. | 
| SpyCloud.CompassApplicationData.infected_path | String | The local path to the malicious software installed on the infected user's system. | 
| SpyCloud.CompassApplicationData.infected_time | Date | The time at which the user's system was infected with malicious software. | 
| SpyCloud.CompassApplicationData.user_sys_domain | String | System domain. This usually comes from Botnet data. | 
| SpyCloud.CompassApplicationData.user_hostname | String | System hostname. This usually comes from Botnet data. | 
| SpyCloud.CompassApplicationData.user_os | String | System OS name. This usually comes from Botnet data. | 
| SpyCloud.CompassApplicationData.user_sys_registered_owner | String | System registered owner name. This usually comes from Botnet data. | 
| SpyCloud.CompassApplicationData.source_id | Number | Numerical breach ID. This correlates directly with the id field in Breach Catalog objects. | 
| SpyCloud.CompassApplicationData.spycloud_publish_date | Date | The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers. | 
| SpyCloud.CompassApplicationData.target_domain | String | SLD extracted from 'target_url' field. | 
| SpyCloud.CompassApplicationData.target_subdomain | String | Subdomain and SLD extracted from 'target_url' field. | 
| SpyCloud.CompassApplicationData.severity | Number | Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned. Possible values are: 2 -&gt; Email only severity. This record is part of an email-only list. 5 -&gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all. 20 -&gt; High severity. This severity value is given to breach records where we have an email address and a plaintext password. 25 -&gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. | 
| SpyCloud.CompassApplicationData.document_id | String | UUID v4 string which uniquely identifies this breach record in our data set. | 
| SpyCloud.CompassApplicationData.email | String | Email address. | 
| SpyCloud.CompassApplicationData.email_domain | String | Domain extracted from 'email_address' field. This is not a SLD, but everything after the '@' symbol. | 
| SpyCloud.CompassApplicationData.email_username | String | Username extracted from 'email' field. This is everything before the '@' symbol. | 
| SpyCloud.CompassApplicationData.domain | String | Domain name. | 

#### Command example

```!spycloud-compass-application-data-get target_application=dummy.greythr.com limit=2```

#### Context Example

```json
{
    "SpyCloud": {
        "CompassDeviceData": [
            {
                "display_resolution": "1280x720",
                "document_id": "c8a11837-808a-4b1e-b9d8-cfba0739c7f5",
                "infected_machine_id": "72aaaec1-afa1-4d9e-838f-abfcbbf3ff82",
                "ip_addresses": [
                    "4.4.4.4"
                ],
                "password": "Tron99***018",
                "password_plaintext": "Tron99***018",
                "password_type": "plaintext",
                "severity": 25,
                "source_id": 41985,
                "spycloud_publish_date": "2023-03-02T00:00:00Z",
                "target_domain": "greythr.com",
                "target_subdomain": "dummy.greythr.com",
                "target_url": "dummy.greythr.com",
                "user_browser": "Chrome (v109.0.5414.120-64, Profile: Profile 1)",
                "user_os": "Windows 10 Pro",
                "username": "345"
            },
            {
                "document_id": "f746b0ba-c765-4a04-b09e-1c42d35ee426",
                "infected_machine_id": "eb36d8f4-b802-416a-9e94-cdb419782b10",
                "infected_path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe",
                "infected_time": "2022-12-29T11:01:47Z",
                "ip_addresses": [
                    "4.4.4.4"
                ],
                "keyboard_languages": "english (india) / english (united states)",
                "password": "welcome@123",
                "password_plaintext": "welcome@123",
                "password_type": "plaintext",
                "severity": 25,
                "source_id": 40883,
                "spycloud_publish_date": "2023-01-06T00:00:00Z",
                "target_domain": "greythr.com",
                "target_subdomain": "dummy.greythr.com",
                "target_url": "dummy.greythr.com",
                "user_browser": "Mozilla Firefox",
                "user_hostname": "LAPPY",
                "user_os": "Windows 10 Pro [x64]",
                "user_sys_registered_owner": "Home",
                "username": "369"
            }
        ]
    }
}
```

#### Human Readable Output

>### Compass Applications - Data

>|Source ID|User Name|Target Domain|Target Subdomain|Password|Password Plaintext|Password Type|Target URL|User Browser|IP Addresses|Infected Machine ID|Infected Path|Infected Time|User Hostname|User OS|User SYS Registered Owner|SpyCloud Publish Date|Document ID|Severity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 41985 | 345 | greythr.com | dummy.greythr.com | Tron99***018 | Tron99***018 | plaintext | dummy.greythr.com | Chrome (v109.0.5414.120-64, Profile: Profile 1) | 4.4.4.4 | 72aaaec1-afa1-4d9e-838f-abfcbbf3ff82 |  |  |  | Windows 10 Pro |  | 2023-03-02T00:00:00Z | c8a11837-808a-4b1e-b9d8-cfba0739c7f5 | 25 |
>| 40883 | 369 | greythr.com | dummy.greythr.com | welcome@123 | welcome@123 | plaintext | dummy.greythr.com | Mozilla Firefox | 4.4.4.4 | eb36d8f4-b802-416a-9e94-cdb419782b10 | C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe | 2022-12-29T11:01:47Z | LAPPY | Windows 10 Pro [x64] | Home | 2023-01-06T00:00:00Z | f746b0ba-c765-4a04-b09e-1c42d35ee426 | 25 |
