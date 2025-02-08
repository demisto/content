Threat Intelligence Platform that connects and interprets intelligence data from open sources, commercial suppliers and industry partnerships .
This integration was integrated and tested with version 2.14 and 3.0 of EclecticIQ Intelligence Center v3.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-eclecticiq-intelligence-center-v3).

## Configure EclecticIQ Intelligence Center v3 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| EclecticIQ Intelligence Center URL (e.g. https://eclecticiq-platform.local) |  | True |
| API user token to authenticate in EclecticIQ Intelligence Center |  | True |
| EclecticIQ Intelligence Center public API version |  | True |
| IP threshold. Minimum maliciousness confidence level to consider the IP address malicious: High, Medium, Low, Safe, Unknown |  | False |
| URL threshold. Minimum maliciousness confidence level to consider the URL malicious: High, Medium, Low, Safe, Unknown |  | False |
| File threshold. Minimum maliciousness confidence level to consider the file malicious: High, Medium, Low, Safe, Unknown |  | False |
| Email threshold. Minimum maliciousness confidence level to consider the email address malicious: High, Medium, Low, Safe, Unknown |  | False |
| Domain threshold. Minimum maliciousness confidence level to consider the domain malicious: High, Medium, Low, Safe, Unknown |  | False |
| Group name in EclecticIQ Intelligence Center to use as entities source |  | False |
| Create sightings automatically in EclecticIQ Intelligence Center when reputation check command executed. |  | False |
| Fetch indicators |  |  |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Feed IDs to fetch | e.g. 12,14,22 | False |
|  |  | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed |  |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Get reputation of IP address observable.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IPv4 to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.IP.Created | Date | Observable creation time. | 
| EclecticIQ.IP.LastUpdated | Date | Observable last update time. | 
| EclecticIQ.IP.Maliciousness | String | Observable maliciousness. | 
| EclecticIQ.IP.Observable | String | Observable value. | 
| EclecticIQ.IP.SourceName | String | Observable source name. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\). | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.Address | String | IP address. | 

#### Command example
```!ip ip="8.8.8.8"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip",
        "Vendor": "EclecticIQ Intelligence Center v3"
    },
    "EclecticIQ": {
        "IP": {
            "Created": "2023-10-09T18:00",
            "LastUpdated": "2023-11-13T15:35",
            "Maliciousness": "unknown",
            "Observable": "8.8.8.8",
            "SourceName": "enricher_task: VirusTotal APIv3 File Hash (Contacted Infrastructure) Enricher; enricher_task: Recorded Future Enricher; group: Testing Group; "
        }
    },
    "IP": {
        "Address": "8.8.8.8"
    }
}
```

#### Human Readable Output

>### EclecticIQ IP reputation - 8.8.8.8
>|created|id|last_updated|maliciousness|platform_link|source_name|type|value|
>|---|---|---|---|---|---|---|---|
>| 2023-10-09T18:00 | 466127 | 2023-11-13T15:35 | unknown | https://ic-playground.eclecticiq.com/main/intel/all/browse/observable?tab=overview&id=466127 | enricher_task: VirusTotal APIv3 File Hash (Contacted Infrastructure) Enricher; enricher_task: Recorded Future Enricher; group: Testing Group;  | ipv4 | 8.8.8.8 |


### url

***
Gets the reputation of a URL observable.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL observable to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.URL.Created | Date | Observable creation time. | 
| EclecticIQ.URL.LastUpdated | Date | Observable last update time. | 
| EclecticIQ.URL.Maliciousness | String | Observable maliciousness. | 
| EclecticIQ.URL.Observable | String | Observable value. | 
| EclecticIQ.URL.SourceName | String | Observable source name. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\). | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| URL.Data | String | URL requested. | 

#### Command example
```!url url="https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/",
        "Score": 0,
        "Type": "url",
        "Vendor": "EclecticIQ Intelligence Center v3"
    },
    "EclecticIQ": {
        "URL": {
            "Created": "2023-06-02T08:14",
            "LastUpdated": "2023-06-02T08:14",
            "Maliciousness": "unknown",
            "Observable": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/",
            "SourceName": "incoming_feed: Elemendar; "
        }
    },
    "URL": {
        "Data": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/"
    }
}
```

#### Human Readable Output

>### EclecticIQ URL reputation - https:<span>//</span>www.ultimatewindowssecurity.com/securitylog/encyclopedia/
>|created|id|last_updated|maliciousness|platform_link|source_name|type|value|
>|---|---|---|---|---|---|---|---|
>| 2023-06-02T08:14 | 119519 | 2023-06-02T08:14 | unknown | https://ic-playground.eclecticiq.com/main/intel/all/browse/observable?tab=overview&id=119519 | incoming_feed: Elemendar;  | uri | https:<span>//</span>www.ultimatewindowssecurity.com/securitylog/encyclopedia/ |


### file

***
Gets the reputation of a file hash observable.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash observable to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.File.Created | Date | Observable creation time. | 
| EclecticIQ.File.LastUpdated | Date | Observable last update time. | 
| EclecticIQ.File.Maliciousness | String | Observable maliciousness. | 
| EclecticIQ.File.Observable | String | Observable value. | 
| EclecticIQ.File.SourceName | String | Observable source name. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\). | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.MD5 | String | Bad MD5 hash. | 
| File.SHA1 | String | Bad SHA1 hash. | 
| File.SHA256 | String | Bad SHA256 hash. | 

#### Command example
```!file file=ae5f156a6f5052494a295c597389dbee```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "ae5f156a6f5052494a295c597389dbee",
        "Score": 0,
        "Type": "file",
        "Vendor": "EclecticIQ Intelligence Center v3"
    },
    "EclecticIQ": {
        "File": {
            "Created": "2023-05-26T09:20",
            "LastUpdated": "2023-05-26T09:20",
            "Maliciousness": "unknown",
            "Observable": "ae5f156a6f5052494a295c597389dbee",
            "SourceName": "enricher_task: Threatcrowd API V2; "
        }
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "ae5f156a6f5052494a295c597389dbee"
            }
        ],
        "MD5": "ae5f156a6f5052494a295c597389dbee"
    }
}
```

#### Human Readable Output

>### EclecticIQ File reputation - ae5f156a6f5052494a295c597389dbee
>|created|id|last_updated|maliciousness|platform_link|source_name|type|value|
>|---|---|---|---|---|---|---|---|
>| 2023-05-26T09:20 | 13 | 2023-05-26T09:20 | unknown | https://ic-playground.eclecticiq.com/main/intel/all/browse/observable?tab=overview&id=13 | enricher_task: Threatcrowd API V2;  | hash-md5 | ae5f156a6f5052494a295c597389dbee |


### eclecticiq-get-entity

***
Query EIC for entity.

#### Base Command

`eclecticiq-get-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| observable_value | Observable value to query related entities. | Optional | 
| entity_title | Text to search inside entity title. | Optional | 
| entity_type | Type of entity to limit query. Possible values are: all, campaign, course-of-action, exploit-target, incident, indicator, sighting, threat-actor, ttp. Default is all. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.Entity.confidence | String | Entity confidence. | 
| EclecticIQ.Entity.created_at | Date | Entity creation time. | 
| EclecticIQ.Entity.description | String | Entity description. | 
| EclecticIQ.Entity.entity_title | String | Entity title. | 
| EclecticIQ.Entity.entity_type | String | Entity type. | 
| EclecticIQ.Entity.impact.type | String | Entity impact type. | 
| EclecticIQ.Entity.impact.value | String | Entity impact value. | 
| EclecticIQ.Entity.impact.value_vocab | String | Entity impact STIX vocabulary. | 
| EclecticIQ.Entity.observables_list.maliciousness | String | Related observable maliciousness. | 
| EclecticIQ.Entity.observables_list.type | String | Related observable type. | 
| EclecticIQ.Entity.observables_list.value | String | Related observable value. | 
| EclecticIQ.Entity.observables_output | String | Related observables string. | 
| EclecticIQ.Entity.relationships_list | Unknown | Entity relationships list. | 
| EclecticIQ.Entity.relationships_output | String | Entity relationships string. | 
| EclecticIQ.Entity.source_name | String | Entity source. | 
| EclecticIQ.Entity.tags_list | Unknown | Entity tags and taxonomies. | 

### email

***
Gets the reputation of an email address observable.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address observable to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.Email.Created | Date | Observable creation time. | 
| EclecticIQ.Email.LastUpdated | Date | Observable last update time. | 
| EclecticIQ.Email.Maliciousness | String | Observable maliciousness. | 
| EclecticIQ.Email.Observable | String | Observable value. | 
| EclecticIQ.Email.SourceName | String | Observable source name. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\). | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 

#### Command example
```!email email=domains@twitter.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "domains@twitter.com",
        "Score": 0,
        "Type": "email",
        "Vendor": "EclecticIQ Intelligence Center v3"
    },
    "EclecticIQ": {
        "Email": {
            "Created": "2023-05-26T09:22",
            "LastUpdated": "2023-05-26T09:22",
            "Maliciousness": "unknown",
            "Observable": "domains@twitter.com",
            "SourceName": "enricher_task: Threatcrowd API V2; "
        }
    },
    "Email": {
        "Address": "domains@twitter.com"
    }
}
```

#### Human Readable Output

>### EclecticIQ Email reputation - domains@twitter.com
>|created|id|last_updated|maliciousness|platform_link|source_name|type|value|
>|---|---|---|---|---|---|---|---|
>| 2023-05-26T09:22 | 1028 | 2023-05-26T09:22 | unknown | https://ic-playground.eclecticiq.com/main/intel/all/browse/observable?tab=overview&id=1028 | enricher_task: Threatcrowd API V2;  | email | domains@twitter.com |


### domain

***
Gets the reputation of a domain observable.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain observable to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.Domain.Created | Date | Observable creation time. | 
| EclecticIQ.Domain.LastUpdated | Date | Observable last update time. | 
| EclecticIQ.Domain.Maliciousness | String | Observable maliciousness. | 
| EclecticIQ.Domain.Observable | String | Observable value. | 
| EclecticIQ.Domain.SourceName | String | Observable source name. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\). | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | Requested Domain. | 

#### Command example
```!domain domain=urlz.fr```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "urlz.fr",
        "Score": 3,
        "Type": "domain",
        "Vendor": "EclecticIQ Intelligence Center v3"
    },
    "Domain": {
        "Malicious": {
            "Description": "EclecticIQ maliciousness confidence level: low",
            "Vendor": "EclecticIQ Intelligence Center v3"
        },
        "Name": "urlz.fr"
    },
    "EclecticIQ": {
        "Domain": {
            "Created": "2023-05-26T09:20",
            "LastUpdated": "2023-05-26T09:20",
            "Maliciousness": "low",
            "Observable": "urlz.fr",
            "SourceName": ""
        }
    }
}
```

#### Human Readable Output

>### EclecticIQ Domain reputation - urlz.fr
>|created|id|last_updated|maliciousness|platform_link|source_name|type|value|
>|---|---|---|---|---|---|---|---|
>| 2023-05-26T09:20 | 43 | 2023-05-26T09:20 | low | https://ic-playground.eclecticiq.com/main/intel/all/browse/observable?tab=overview&id=43 |  | domain | urlz.fr |


### eclecticiq-create-sighting

***
Create a sighting entity on EIC.
Must contain at least one observable.

#### Base Command

`eclecticiq-create-sighting`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| observable_value | Observable value to connect to Sighting. | Required | 
| observable_type | Observable type. Possible values are: domain, email, email-subject, file, hash, hash-md5, hash-sha1, hash-sha256, hash-sha512, host, ipv4, ipv6, mutex, port, process, uri, winregistry. | Required | 
| observable_maliciousness | Observable maliciousness. Possible values are: Malicious (High confidence), Malicious (Medium confidence), Malicious (Low confidence), Safe, Unknown. | Required | 
| sighting_title | Sighting title. | Required | 
| sighting_description | Sighting description. | Optional | 
| sighting_confidence | Sighting confidence. Possible values are: None, Unknown, Low, Medium, High. | Required | 
| sighting_impact | Sighting impact. Possible values are: None, Unknown, Low, Medium, High. | Required | 
| sighting_tag | Sighting tags, use comma (",") as delimeter between tags. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.Sightings.SightingDetails.ObservableMaliciousness | String | Sighting related observable maliciousness. | 
| EclecticIQ.Sightings.SightingDetails.ObservableType | String | Sighting related observable type. | 
| EclecticIQ.Sightings.SightingDetails.ObservableValue | String | Sighting related observable value. | 
| EclecticIQ.Sightings.SightingDetails.SightingTitle | String | Sighting title. | 
| EclecticIQ.Sightings.SightingId | String | Sighting entity ID. | 

### eclecticiq-create-indicator

***
Create an indicator entity on EIC.
Must contain at least one observable.

#### Base Command

`eclecticiq-create-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_title | Indicator title. | Required | 
| indicator_description | Indicator description. | Optional | 
| indicator_confidence | Indicator confidence. Possible values are: None, Unknown, Low, Medium, High. | Required | 
| indicator_impact | Indicator impact. Possible values are: None, Unknown, Low, Medium, High. | Required | 
| indicator_tag | Indicator tags, use comma (",") as delimeter between tags. | Optional | 
| observable_value | Observable value to connect to Indicator. | Required | 
| observable_type | Observable type. Possible values are: domain, email, email-subject, file, hash, hash-md5, hash-sha1, hash-sha256, hash-sha512, host, ipv4, ipv6, mutex, port, process, uri, winregistry. | Required | 
| observable_maliciousness | Observable maliciousness. Possible values are: Malicious (High confidence), Malicious (Medium confidence), Malicious (Low confidence), Safe, Unknown. | Required | 
| observable_dictionary | Any amount observables in format: [{"value":"192.168.0.192", "type":"ipv4", "maliciousness":"medium"}]. Observable types use as in EclecticIQ. Observable maliciousness could be: high, medium, low, safe, unknown. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.Indicators.IndicatorId | String | Indicator entity ID. | 
| EclecticIQ.Indicators.IndicatorTitle | String | Indicator entity title. | 
| EclecticIQ.Indicators.ObservablesList.observable_classification | String | Indicator related observable classification. | 
| EclecticIQ.Indicators.ObservablesList.observable_maliciousness | String | Indicator related observable maliciousness. | 
| EclecticIQ.Indicators.ObservablesList.observable_type | String | Indicator related observable type. | 
| EclecticIQ.Indicators.ObservablesList.observable_value | String | Indicator related observable value. | 

### eclecticiq-get-entity-by-id

***
Query EclecticIQ Intelligence Center for entity by its ID.

#### Base Command

`eclecticiq-get-entity-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Entity ID in EclecticIQ format, for example: a86f8393-eff6-4b31-b203-f63152be5a43. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.EntityById.confidence | String | Entity confidence. | 
| EclecticIQ.EntityById.created_at | Date | Entity creation time. | 
| EclecticIQ.EntityById.description | String | Entity description. | 
| EclecticIQ.EntityById.entity_title | String | Entity title. | 
| EclecticIQ.EntityById.entity_type | String | Entity type. | 
| EclecticIQ.EntityById.impact | String | Entity impact. | 
| EclecticIQ.EntityById.observables_list.maliciousness | String | Related observable maliciousness. | 
| EclecticIQ.EntityById.observables_list.type | String | Related observable type. | 
| EclecticIQ.EntityById.observables_list.value | String | Related observable value. | 
| EclecticIQ.EntityById.relationships_list | Unknown | Entity relationships list. | 
| EclecticIQ.EntityById.source_name | String | Entity source. | 
| EclecticIQ.EntityById.tags_list | Unknown | Entity tags and taxonomies. | 

### eclecticiq-request-get

***
Make HTTP GET request to EclecticIQ Intelligence Center.

#### Base Command

`eclecticiq-request-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | EclecticIQ URI excluding Intelligence Cetner address but including API version and params if needed. e.g. /private/status. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.GET.ReplyBody | Unknown | GET reply body. | 
| EclecticIQ.GET.ReplyStatus | String | GET reply status code. | 
| EclecticIQ.GET.URI | String | GET reply requested URI. | 

#### Command example
```!eclecticiq-request-get uri=/api/v2/datasets```
#### Context Example
```json
{
    "EclecticIQ": {
        "GET": {
            "ReplyBody": {
                "count": 100,
                "data": [...],
                "limit": 100,
                "offset": 0,
                "total_count": 113
            },
            "ReplyStatus": "200",
            "URI": "/api/v2/datasets"
        }
    }
}
```

#### Human Readable Output

>### EclecticIQ GET action to endpoint /api/v2/datasets exectued. Reply status: 200

### eclecticiq-request-post

***
Make HTTP POST request to EclecticIQ Intelligence Center.

#### Base Command

`eclecticiq-request-post`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | EclecticIQ URI excluding Intelligence Cetner address but including API version and params if needed. | Required | 
| body | JSON payload. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.POST.ReplyBody | String | POST reply body. | 
| EclecticIQ.POST.ReplyStatus | String | POST reply status code. | 
| EclecticIQ.POST.URI | String | POST reply requested URI. | 

#### Command example
```!eclecticiq-request-post uri=/api/v2/datasets body=`{"data": {"workspaces": "1", "name": "test11112"}}```
#### Context Example
```json
{
    "EclecticIQ": {
        "POST": {
            "ReplyBody": {
                "data": {...}
            },
            "ReplyStatus": "201",
            "URI": "/api/v2/datasets"
        }
    }
}
```



#### Human Readable Output

>### EclecticIQ POST action to endpoint /api/v2/datasets exectued. Reply status: 201


### eclecticiq-request-put

***
Make HTTP PUT request to EclecticIQ Intelligence Center.

#### Base Command

`eclecticiq-request-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | EclecticIQ URI excluding Intelligence Cetner address but including API version and params if needed. | Required | 
| body | JSON payload. | Optional | 

#### Context Output

| **Path**                   | **Type** | **Description**          |
|----------------------------| --- |--------------------------|
| EclecticIQ.PUT.ReplyBody   | String | PUT reply body.          | 
| EclecticIQ.PUT.ReplyStatus | String | PUT reply status code.   | 
| EclecticIQ.PUT.URI         | String | PUT reply requested URI. | 

#### Command example
```!eclecticiq-request-put uri=/api/v2/datasets body=`{"data": {"workspaces": "1", "name": "test11112"}}```
#### Context Example
```json
{
    "EclecticIQ": {
        "PUT": {
            "ReplyBody": {
                "data": {...}
            },
            "ReplyStatus": "200",
            "URI": "/api/v2/datasets"
        }
    }
}
```



#### Human Readable Output

>### EclecticIQ PUT action to endpoint /api/v2/datasets exectued. Reply status: 200


### eclecticiq-request-patch

***
Make HTTP PATCH request to EclecticIQ Intelligence Center.

#### Base Command

`eclecticiq-request-patch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | EclecticIQ URI excluding Intelligence Cetner address but including API version and params if needed. | Required | 
| body | JSON payload. | Optional | 

#### Context Output

| **Path**                     | **Type** | **Description**            |
|------------------------------| --- |----------------------------|
| EclecticIQ.PATCH.ReplyBody   | String | PATCH reply body.          | 
| EclecticIQ.PATCH.ReplyStatus | String | PATCH reply status code.   | 
| EclecticIQ.PATCH.URI         | String | PATCH reply requested URI. | 

#### Command example
```!eclecticiq-request-patch uri=/api/v2/datasets/1 body=`{"data": {"workspaces": "1", "name": "test11112"}}```
#### Context Example
```json
{
    "EclecticIQ": {
        "PATCH": {
            "ReplyBody": {
                "data": {...}
            },
            "ReplyStatus": "200",
            "URI": "/api/v2/datasets/1"
        }
    }
}
```



#### Human Readable Output

>### EclecticIQ PATCH action to endpoint /api/v2/datasets/1 exectued. Reply status: 200


### eclecticiq-request-delete

***
Make HTTP DELETE request to EclecticIQ Intelligence Center.

#### Base Command

`eclecticiq-request-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | EclecticIQ URI excluding Intelligence Cetner address but including API version and params if needed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.DELETE.ReplyStatus | String | DELETE reply status code. | 
| EclecticIQ.DELETE.URI | String | DELETE reply requested URI. | 

### eclecticiq-get-indicators

***
Get last block of Indicators from configured to fetch Outgoing feed.

#### Base Command

`eclecticiq-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
#### Command example
```!eclecticiq-get-indicators```
#### Human Readable Output

>### Indicators collected from first block of feed:[{'id': '11', 'created_at': '2023-06-26T15:23:19.737166+00:00', 'update_strategy': 'REPLACE', 'packaging_status': 'SUCCESS', 'name': 'splunk-test'}]
>**No entries.**


## Breaking changes from the previous version of this integration - EclecticIQ Intelligence Center v3
Integration rebuild with added functionality to fetch indicators from outgoing feeds and with many new commands. Integration is not compatible with EclecticIQ integration v2.