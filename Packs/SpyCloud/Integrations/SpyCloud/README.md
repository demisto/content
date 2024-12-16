With the SpyCloud integration, data from breaches can be pulled and further processed in Playbooks. Filtering parameters can be used to filter the data set
This integration was integrated and tested with version 2 of SpyCloud

## Configure SpyCloud in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Base URL of SpyCloud | True |
| API Key of SpyCloud | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### spycloud-list-breaches
***
Lists the breaches identified. By default this lists all breaches known in Spycloud. With the arguments it's possible to scope the results on date and keywords.


#### Base Command

`spycloud-list-breaches`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Give a keyword to search for in the dataset. Default is empty. | Optional | 
| since | Search the dataset since this date. Format is yyyy-mm-dd and default value is 2010-01-01. Default is 2010-01-01. | Optional | 
| until | Search the dataset until this date. Format is yyyy-mm-dd and default value is 2100-01-01 (aka get everything). Default is 2100-01-01. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.Breaches.uuid | String | unique ID | 
| SpyCloud.Breaches.title | String | Breach title | 
| SpyCloud.Breaches.type | String | Type of breach | 
| SpyCloud.Breaches.description | String | Summary of the breach/threat | 
| SpyCloud.Breaches.acquisition_date | Date | When the breach data was acquired | 
| SpyCloud.Breaches.site | String | The website that was breached | 
| SpyCloud.Breaches.spycloud_publish_date | Date | Publication date | 
| SpyCloud.Breaches.num_records | Number | Number of records in the breach | 
| SpyCloud.Breaches.id | Number | Unique breach ID | 

#### Command example
```!spycloud-list-breaches```
#### Context Example
```json
{
    "SpyCloud": {
        "Breaches": [
            {
                "acquisition_date": "2021-01-22T00:00:00Z",
                "description": "In x time, site Y was breached",
                "id": 11111,
                "num_records": 45810,
                "site": "examplers.com",
                "spycloud_publish_date": "2021-05-19T00:00:00Z",
                "title": "Cool title",
                "type": "PRIVATE",
                "uuid": "1111111-2222-34567-aaaa-9282829dddde"
            },
        ]
    }
}
```

#### Human Readable Output

>### Results
>|acquisition_date|description|id|num_records|site|spycloud_publish_date|title|type|uuid|
>|---|---|---|---|---|---|---|---|---|
>| 2021-05-19T00:00:00Z | In x time, site Y was breached | 35911 | 45810 | examplers.com | 2022-05-19T00:00:00Z | Cool title | PRIVATE | 1111111-2222-34567-aaaa-9282829dddde |


### spycloud-get-breach-data
***
Retrieves the breach details. While very similar to list-breaches, this command obtains one specific breach, which is easier for automation tasks


#### Base Command

`spycloud-get-breach-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The breach ID to filter on. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.Breaches.uuid | String | Unique ID | 
| SpyCloud.Breaches.title | String | Breach title | 
| SpyCloud.Breaches.type | String | Type of breach | 
| SpyCloud.Breaches.description | String | Summary of the breach | 
| SpyCloud.Breaches.acquisition_date | Date | Acquired date | 
| SpyCloud.Breaches.site | String | Title of the breach | 
| SpyCloud.Breaches.spycloud_publish_date | Date | Publication date | 
| SpyCloud.Breaches.num_records | Number | Number of records in breach | 
| SpyCloud.Breaches.id | Number | Unique breach ID | 

#### Command example
```!spycloud-get-breach-data id=37666```
#### Context Example
```json
{
    "SpyCloud": {
        "Breaches": {
            "acquisition_date": "2020-05-13T00:00:00Z",
            "description": "Cool description of the threat",
            "id": 37666,
            "num_records": 802751,
            "site": "n/a",
            "spycloud_publish_date": "2021-05-18T00:00:00Z",
            "title": "Cool title",
            "type": "PRIVATE",
            "uuid": "11111111-2222-3333-4444-555555555555"
        }
    }
}
```

#### Human Readable Output

>### Results
>|acquisition_date|description|id|num_records|site|spycloud_publish_date|title|type|uuid|
>|---|---|---|---|---|---|---|---|---|
>| 2021-05-13T00:00:00Z | Cool description of the threat | 37666 | 802751 | n/a | 2021-05-18T00:00:00Z | Cool title | PRIVATE | 11111111-2222-3333-44444444444444444 |


### spycloud-domain-data
***
Get all the data from a monitored domain and the breaches occurred that relates with it. Can be scoped by domain, type and severity

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`spycloud-domain-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to search for in the data. | Required | 
| type | Allowed values: corporate, infected. Default is corporate. Infected returns the infected employees and customers. Default is corporate. | Optional | 
| severity | Allowed values: 2, 5, 10, 15, 20, 25. Default is 2. Default is 2. | Optional | 
| since | The starting point for a date range query on the spycloud_publish_date. The value provided must follow the standard ISO 8601 date format (yyyy-mm-dd). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.Domain.document_id | String | The unique ID of the identified record | 
| SpyCloud.Domain.spycloud_publish_date | Date | The date SpyCloud has found the data record | 
| SpyCloud.Domain.username | String | The username that was found in the breach dataset | 
| SpyCloud.Domain.email | String | The email that was found in the breach dataset | 
| SpyCloud.Domain.infected_time | String | The date the user got infected | 
| SpyCloud.Domain.target_url | String | Which URL the credentials are for | 
| SpyCloud.Domain.source_id | String | breach source ID | 
| SpyCloud.Domain.password_plaintext | String | Plaintext password identified | 

#### Command example
```!spycloud-domain-data domain=example.com since=2022-05-01```
#### Context Example
```json
{
    "SpyCloud": {
        "Results": [
            {
                "document_id": "11111111-2222-3333-4444-555555555555",
                "email": "sales@example.com",
                "infected_time": "empty",
                "password_plaintext": "empty",
                "source_id": 37666,
                "spycloud_publish_date": "2021-01-12T00:00:00Z",
                "target_domain": "empty",
                "username": "empty"
            },
            {
                "document_id": "11111111-2222-3333-4444-555555555555",
                "email": "support@example.com",
                "infected_time": "empty",
                "password_plaintext": "empty",
                "source_id": 37666,
                "spycloud_publish_date": "2022-01-12T00:00:00Z",
                "target_domain": "empty",
                "username": "empty"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|document_id|email|infected_time|password_plaintext|source_id|spycloud_publish_date|target_domain|username|
>|---|---|---|---|---|---|---|---|
>| 11111111-2222-3333-4444-555555555555 | sales@example.com | empty | empty | 37518 | 2022-01-12T00:00:00Z | empty | empty |
>| 11111111-2222-3333-4444-555555555555 | support@example.com | empty | empty | 37518 | 2022-01-12T00:00:00Z | empty | empty |


### spycloud-email-data
***
Get all the data from a monitored email address and the breaches occurred that relates with it. Can be scoped by date, severity and breach


#### Base Command

`spycloud-email-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| emailaddr | Email address to search for. | Required | 
| severity | Allowed values: 2, 5, 10, 15, 20, 25. Default is 2. Default is 2. | Optional | 
| breach_id | The breach ID to search in. Default is empty. | Optional | 
| since | The starting point for a date range query on the spycloud_publish_date. The value provided must follow the standard ISO 8601 date format (yyyy-mm-dd). | Required | 
| until | The until date for a date range query on the spycloud_publish_date. The value provided must follow the standard ISO 8601 date format (yyyy-mm-dd). Default is 2100-01-01. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.Emails.document_id | String | The unique ID of the identified record | 
| SpyCloud.Emails.spycloud_publish_date | Date | The date SpyCloud has found the data record | 
| SpyCloud.Emails.username | String | The username that was found in the breach dataset | 
| SpyCloud.Emails.email | String | The email that was found in the breach dataset | 
| SpyCloud.Emails.source_id | String | breach source ID | 
| SpyCloud.Emails.domain | String | The domain that the user/pass is used on | 
| SpyCloud.Emails.password | String | Password found. Can be plaintext or hashed, good to check | 
| SpyCloud.Emails.user_browser | String | The browser of the user | 
| SpyCloud.Emails.target_url | String | The target url of the credentials | 

#### Command example
```!spycloud-email-data emailaddr=john.doe@example.com since=2020-08-01 until=2021-02-01```
#### Context Example
```json
{
    "SpyCloud": {
        "Emails": [
            {
                "document_id": "11111111-2222-3333-4444-555555555555",
                "domain": "example.com",
                "email": "john.doe@example.com",
                "password": "empty",
                "source_id": 38666,
                "spycloud_publish_date": "2021-10-21T00:00:00Z",
                "target_url": "empty",
                "user_browser": "empty",
                "username": "empty"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|document_id|domain|email|password|source_id|spycloud_publish_date|target_url|user_browser|username|
>|---|---|---|---|---|---|---|---|---|
>| 11111111-2222-3333-4444-555555555555 | example.com | john.doe@example.com | empty | 38666 | 2021-10-21T00:00:00Z | empty | empty | empty 


### spycloud-watchlist-data
***
Get all the data from a watchlist.


#### Base Command

`spycloud-watchlist-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_type | Allowed values are ip, domain, email. | Required | 
| type | Allowed values: corporate or infected. Default is corporate. Default is corporate. | Optional | 
| breach_id | The breach ID to search in. Default is empty. | Optional | 
| since | The starting point for a date range query on the spycloud_publish_date. The value provided must follow the standard ISO 8601 date format (yyyy-mm-dd). | Required | 
| until | The until date for a date range query on the spycloud_publish_date. The value provided must follow the standard ISO 8601 date format (yyyy-mm-dd). Default is 2100-01-01. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpyCloud.Watchlist.document_id | String | The unique ID of the identified record | 
| SpyCloud.Watchlist.username | String | The username of the identified record | 
| SpyCloud.Watchlist.target_url | String | The targeted url | 
| SpyCloud.Watchlist.breach_id | String | The breach ID | 
| SpyCloud.Watchlist.password | String | The password of the user being exposed | 
| SpyCloud.Watchlist.spycloud_publish_date' | String | Date when Spycloud published the breach | 
| SpyCloud.Watchlist.email | String | The email address involved \(if email watchlist type selected\) | 
| SpyCloud.Watchlist.domain | String | The domain involved of the watchlist \(if that type is selected\) | 

#### Command example
```!spycloud-watchlist-data watchlist_type=email since=2022-02-11```
#### Context Example
```json
{
    "SpyCloud": {
        "Watchlist": {
            "breach_id": 38666,
            "document_id": "11111111-2222-3333-4444-555555555555",
            "domain": "hotmail.com",
            "email": "john.doe@hotmail.com",
            "password": "empty",
            "spycloud_publish_date": "2020-03-03T00:00:00Z",
            "target_url": "empty",
            "username": "empty"
        }
    }
}
```

#### Human Readable Output

>### Results
>|breach_id|document_id|domain|email|password|spycloud_publish_date|target_url|username|
>|---|---|---|---|---|---|---|---|
>| 38666 | 11111111-2222-3333-4444-555555555555 | hotmail.com | john.doe@hotmail.com | empty | 2020-03-03T00:00:00Z | empty | empty |
