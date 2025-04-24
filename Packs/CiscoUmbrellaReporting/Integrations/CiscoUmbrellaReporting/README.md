## Cisco Umbrella Reporting

Use Cisco Umbrella's Reporting to monitor your Umbrella integration and gain a better understanding of your Umbrella usage. Gain insights into request activity and blocked activity, determining which of your identities are generating blocked requests. Reports help build actionable intelligence in addressing security threats including changes in usage trends over time.

The Umbrella Reporting v2 API provides visibility into your core network and security activities and Umbrella logs. This integration was integrated and tested with version v2 of Cisco-umbrella-reporting.

## Configure Cisco Umbrella Reporting in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API URL | Cisco Umbrella Reporting API base URL. | True |
| API Key | API Key | True |
| API Secret | API Secret | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### umbrella-reporting-destination-list

***
List of destinations ordered by the number of requests made in descending order.

#### Base Command

`umbrella-reporting-destination-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| traffic_type | Specify the type of traffic. By default, all supported traffic types are included. Possible values are: dns, proxy, firewall, ip. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| ip | An IP address. | Optional | 
| urls | A URL or comma-separated list of URLs. | Optional | 
| ports | A port number or comma-separated list of port numbers. | Optional | 
| sha256 | A SHA-256 hash. | Optional | 
| threats | A threat name or comma-separated list of threat names. | Optional | 
| threat_types | A threat type or comma-separated list of threat types. | Optional | 
| amp_disposition | An Advanced Malware Protection (AMP) disposition string. Possible values are: clean, malicious, unknown. | Optional | 
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| categories | A comma-separated list of category ids to filter on. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.Destination.count | Number | Total number of requests made for this destination. | 
| UmbrellaReporting.Destination.domain | String | Destination. | 
| UmbrellaReporting.Destination.bandwidth | Number | The total bandwidth of proxy requests uploaded and downloaded for this destination. | 
| UmbrellaReporting.Destination.rank | Number | The rank of the result based on the number of requests. | 
| UmbrellaReporting.Destination.policycategories.id | Number | ID of the category. | 
| UmbrellaReporting.Destination.policycategories.label | String | The human readable label of the category. | 
| UmbrellaReporting.Destination.policycategories.type | String | The type of category. | 
| UmbrellaReporting.Destination.policycategories.deprecated | Boolean | Whether the category is a legacy category. | 
| UmbrellaReporting.Destination.policycategories.integration | Boolean | Whether the category is an integration. | 
| UmbrellaReporting.Destination.categories.id | Number | ID of the category. | 
| UmbrellaReporting.Destination.categories.label | String | The human readable label of the category. | 
| UmbrellaReporting.Destination.categories.type | String | The type of category. | 
| UmbrellaReporting.Destination.categories.deprecated | Boolean | Whether the category is a legacy category. | 
| UmbrellaReporting.Destination.categories.integration | Boolean | Whether the category is an integration. | 
| UmbrellaReporting.Destination.counts.allowedrequests | Number | Number of requests that were allowed. | 
| UmbrellaReporting.Destination.counts.blockedrequests | Number | Number of requests that were blocked. | 
| UmbrellaReporting.Destination.counts.requests | Number | Total number of requests. | 

#### Command example
```!umbrella-reporting-destination-list limit=2```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "Destination": [
            {
                "bandwidth": null,
                "categories": [
                    {
                        "deprecated": false,
                        "id": 167,
                        "integration": false,
                        "label": "Computers and Internet",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 123,
                        "integration": false,
                        "label": "Infrastructure and Content Delivery Networks",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 148,
                        "integration": false,
                        "label": "Application",
                        "type": "application"
                    },
                    {
                        "deprecated": true,
                        "id": 25,
                        "integration": false,
                        "label": "abc/efgh",
                        "type": "content"
                    },
                    {
                        "deprecated": true,
                        "id": 32,
                        "integration": false,
                        "label": "Business Services",
                        "type": "content"
                    }
                ],
                "count": 1286,
                "counts": {
                    "allowedrequests": 1286,
                    "blockedrequests": 0,
                    "requests": 1286
                },
                "domain": "dummy.domain.com",
                "policycategories": [],
                "rank": 1
            },
            {
                "bandwidth": null,
                "categories": [
                    {
                        "deprecated": false,
                        "id": 163,
                        "integration": false,
                        "label": "Business and Industry",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 167,
                        "integration": false,
                        "label": "Computers and Internet",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 142,
                        "integration": false,
                        "label": "Online Meetings",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 148,
                        "integration": false,
                        "label": "Application",
                        "type": "application"
                    },
                    {
                        "deprecated": true,
                        "id": 25,
                        "integration": false,
                        "label": "abc/efgh",
                        "type": "content"
                    },
                    {
                        "deprecated": true,
                        "id": 32,
                        "integration": false,
                        "label": "Business Services",
                        "type": "content"
                    }
                ],
                "count": 1003,
                "counts": {
                    "allowedrequests": 1003,
                    "blockedrequests": 0,
                    "requests": 1003
                },
                "domain": "dummy.domain.com",
                "policycategories": [],
                "rank": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Destination List
>|Destination|Category|Allowed|Blocked|Requests|
>|---|---|---|---|---|
>| www.cisco.com | Computers and Internet, Infrastructure and Content Delivery Networks, Application, abc/efgh, Business Services | 1286 | 0 | 1286 |
>| presence.teams.microsoft.com | Business and Industry, Computers and Internet, Online Meetings, Application, abc/efgh, Business Services | 1003 | 0 | 1003 |


### umbrella-reporting-category-list

***
List of categories ordered by the number of requests made matching the categories in descending order.

#### Base Command

`umbrella-reporting-category-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| traffic_type | Specify the type of traffic. By default, all supported traffic types are included. Possible values are: dns, proxy, ip. | Optional | 
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| urls | A URL or comma-separated list of URLs. | Optional | 
| ip | An IP address. | Optional | 
| sha256 | A SHA-256 hash. | Optional | 
| threats | A threat name or comma-separated list of threat names. | Optional | 
| threat_types | A threat type or comma-separated list of threat types. | Optional | 
| amp_disposition | An Advanced Malware Protection (AMP) disposition string. Possible values are: clean, malicious, unknown. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50.| Optional | 
| categories | A comma-separated list of category ids to filter on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.Category.count | Number | Number of requests made that match this category. | 
| UmbrellaReporting.Category.bandwidth | String | The total bandwidth of proxy requests uploaded and downloaded for this category. | 
| UmbrellaReporting.Category.category.id | Number | Category ID. | 
| UmbrellaReporting.Category.category.type | String | Category type. | 
| UmbrellaReporting.Category.category.label | String | Category label. | 
| UmbrellaReporting.Category.category.integration | Boolean | Category integration. | 
| UmbrellaReporting.Category.category.deprecated | String | Category deprecated. | 
| UmbrellaReporting.Category.rank | Number | Rank of the category. | 

#### Command example
```!umbrella-reporting-category-list limit=2```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "Category": [
            {
                "bandwidth": 7974662,
                "category": {
                    "deprecated": false,
                    "id": 148,
                    "integration": false,
                    "label": "Application",
                    "type": "application"
                },
                "count": 32446,
                "rank": 1
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 25,
                    "integration": false,
                    "label": "abc/efgh",
                    "type": "content"
                },
                "count": 26112,
                "rank": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Category List
>|Category|Type|Activity|
>|---|---|---|
>| Application | application | 32446 |
>| abc/efgh | content | 26112 |


### umbrella-reporting-identity-list

***
List of identities ordered by the number of requests made matching the categories in descending order.

#### Base Command

`umbrella-reporting-identity-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| traffic_type | Specify the type of traffic. By default, all supported traffic types are included. Possible values are: dns, proxy, firewall, ip. | Optional | 
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| urls | A URL or comma-separated list of URLs. | Optional | 
| ip | An IP address. | Optional | 
| ports | A port number or comma-separated list of port numbers. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| sha256 | A SHA-256 hash. | Optional | 
| threats | A threat name or comma-separated list of threat names. | Optional | 
| threat_types | A threat type or comma-separated list of threat types. | Optional | 
| amp_disposition | An Advanced Malware Protection (AMP) disposition string. Possible values are: clean, malicious, unknown. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| categories | A comma-separated list of category ids to filter on. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.Identity.requests | Number | Total number of requests made by this identity. | 
| UmbrellaReporting.Identity.bandwidth | Number | The total bandwidth of proxy requests uploaded and downloaded for this identity. | 
| UmbrellaReporting.Identity.rank | Number | The rank of the result based on the number of requests. | 
| UmbrellaReporting.Identity.counts.allowedrequests | Number | Number of requests that were allowed. | 
| UmbrellaReporting.Identity.counts.blockedrequests | Number | Number of requests that were blocked. | 
| UmbrellaReporting.Identity.counts.requests | Number | Total number of requests. | 
| UmbrellaReporting.Identity.identity.id | Number | Identity ID. | 
| UmbrellaReporting.Identity.identity.type.id | Number | Origin type for the identity. | 
| UmbrellaReporting.Identity.identity.type.type | String | Origin type name for the identity. | 
| UmbrellaReporting.Identity.identity.type.label | String | Origin type label for the identity. | 
| UmbrellaReporting.Identity.identity.label | String | Label for the identity. | 
| UmbrellaReporting.Identity.identity.deleted | Boolean | Indicates whether the identity was deleted. | 

#### Command example
```!umbrella-reporting-identity-list limit=2```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "Identity": [
            {
                "bandwidth": 7974662,
                "counts": {
                    "allowedrequests": 29540,
                    "blockedrequests": 72,
                    "requests": 29753
                },
                "identity": {
                    "deleted": false,
                    "id": 589064228,
                    "label": "DESKTOP-IIQVPJ7",
                    "type": {
                        "id": 9,
                        "label": "Roaming Computers",
                        "type": "roaming"
                    }
                },
                "rank": 1,
                "requests": 29753
            },
            {
                "bandwidth": null,
                "counts": {
                    "allowedrequests": 17950,
                    "blockedrequests": 59,
                    "requests": 18082
                },
                "identity": {
                    "deleted": false,
                    "id": 593805843,
                    "label": "S\u2019s MacBook Pro",
                    "type": {
                        "id": 9,
                        "label": "Roaming Computers",
                        "type": "roaming"
                    }
                },
                "rank": 2,
                "requests": 18082
            }
        ]
    }
}
```

#### Human Readable Output

>### Identities List
>|Identity|Requests|
>|---|---|
>| DESKTOP-IIQVPJ7 | 29753 |
>| S’s MacBook Pro | 18082 |


### umbrella-reporting-event-type-list

***
List of event types ordered by the number of requests made for each type of event in descending order. The event types are: domain_security, domain_integration, url_security, url_integration, cisco_amp and antivirus.

#### Base Command

`umbrella-reporting-event-type-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| urls | A URL or comma-separated list of URLs. | Optional | 
| ip | An IP address. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| threats | A threat name or comma-separated list of threat names. | Optional | 
| threat_types | A threat type or comma-separated list of threat types. | Optional | 
| amp_disposition | An Advanced Malware Protection (AMP) disposition string. Possible values are: clean, malicious, unknown. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| categories | A comma-separated list of category ids to filter on. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.EventType.eventtype | String | The event type. One of "domain_security", "domain_integration", "url_security", "url_integration", "cisco_amp" and "antivirus". | 
| UmbrellaReporting.EventType.count | Number | Number of requests made that match this event type. | 

#### Command example
```!umbrella-reporting-event-type-list```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "EventType": [
            {
                "count": 2,
                "eventtype": "domain_security"
            },
            {
                "count": 0,
                "eventtype": "url_integration"
            },
            {
                "count": 0,
                "eventtype": "url_security"
            },
            {
                "count": 0,
                "eventtype": "antivirus"
            },
            {
                "count": 0,
                "eventtype": "application"
            },
            {
                "count": 0,
                "eventtype": "cisco_amp"
            },
            {
                "count": 0,
                "eventtype": "domain_integration"
            }
        ]
    }
}
```

#### Human Readable Output

>### Event Type List
>|Event Type|Count|
>|---|---|
>| domain_security | 2 |
>| url_integration | 0 |
>| url_security | 0 |
>| antivirus | 0 |
>| application | 0 |
>| cisco_amp | 0 |
>| domain_integration | 0 |


### umbrella-reporting-file-list

***
List of files within a time frame. Only returns proxy data.

#### Base Command

`umbrella-reporting-file-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| urls | A URL or comma-separated list of URLs. | Optional | 
| ip | An IP address. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| sha256 | A SHA-256 hash. | Optional | 
| amp_disposition | An Advanced Malware Protection (AMP) disposition string. Possible values are: clean, malicious, unknown. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| categories | A comma-separated list of category ids to filter on. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.File.requests | Number | Number of requests. | 
| UmbrellaReporting.File.identitycount | Number | Number of identities for entry. | 
| UmbrellaReporting.File.sha256 | String | SHA256 for entry. | 
| UmbrellaReporting.File.filenames | Unknown | Array of filenames for entry. | 
| UmbrellaReporting.File.filetypes | Unknown | Array of file types for entry. | 
| UmbrellaReporting.File.categories.id | Number | ID of the category. | 
| UmbrellaReporting.File.categories.label | String | The human readable label of the category. | 
| UmbrellaReporting.File.categories.type | String | The type of category. | 
| UmbrellaReporting.File.categories.deprecated | Boolean | Whether the category is a legacy category. | 
| UmbrellaReporting.File.categories.integration | Boolean | Whether the category is an integration. | 

#### Command example
```!umbrella-reporting-file-list limit=2```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "File": [
            {
                "categories": [
                    {
                        "deprecated": false,
                        "id": 142,
                        "integration": false,
                        "label": "Online Meetings",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 148,
                        "integration": false,
                        "label": "Application",
                        "type": "application"
                    }
                ],
                "filenames": [
                    "AnyDesk.exe"
                ],
                "filetypes": [],
                "identitycount": 1,
                "requests": 2,
                "sha256": "dummy_sha256"
            }
        ]
    }
}
```

#### Human Readable Output

>### File List
>|Requests|Identity Count|SHA256|Category|Category Type|File Name|
>|---|---|---|---|---|---|
>| 2 | 1 | 94fe42af4a67ed5be45bd7913d8a8aebc4e35afddd5675d01bd37df8e9b399ae | Online Meetings, Application | content, application | AnyDesk.exe |


### umbrella-reporting-threat-list

***
List of top threats within a time frame. Returns both DNS and Proxy data.

#### Base Command

`umbrella-reporting-threat-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| traffic_type | Specify the type of traffic. By default, all supported traffic types are included. Possible values are: dns, proxy. | Optional | 
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| ip | An IP address. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| threats | A threat name or comma-separated list of threat names. | Optional | 
| threat_types | A threat type or comma-separated list of threat types. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| categories | A comma-separated list of category ids to filter on. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.Threat.threat | String | The threat name. | 
| UmbrellaReporting.Threat.threattype | String | The threat type. | 
| UmbrellaReporting.Threat.count | Number | The number of requests for that threat name. | 

#### Command example
```!umbrella-reporting-threat-list limit=1```

#### Context Example
```json
{
   "UmbrellaReporting":{
      "Threat":[
        {
            "threat": "",
            "threattype": "Adware",
            "count": 1
        }
    ]
   }
}
```
#### Human Readable Output
>### Threat List
| **Threat Type** | **Count** |
|---|---|
| Adware | 1 |

### umbrella-reporting-activity-list

***
List all activity entries (dns/proxy/firewall/ip/intrusion/amp) within the time frame.

#### Base Command

`umbrella-reporting-activity-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| urls | A URL or comma-separated list of URLs. | Optional | 
| ip | An IP address. | Optional | 
| ports | A port number or comma-separated list of port numbers. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| file_name | A string that identifies a filename. Filter the request by the filename. Supports globbing or use of the wildcard character (''). The asterisk (*) matches zero or more occurrences of any character. | Optional | 
| threats | A threat name or comma-separated list of threat names. | Optional | 
| threat_types | A threat type or comma-separated list of threat types. | Optional | 
| amp_disposition | An Advanced Malware Protection (AMP) disposition string. Possible values are: clean, malicious, unknown. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| categories | A comma-separated list of category ids to filter on. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.Activity.type | String | Type of the request. | 
| UmbrellaReporting.Activity.externalip | String | External IP address for entry. | 
| UmbrellaReporting.Activity.internalip | String | Internal IP address for entry. | 
| UmbrellaReporting.Activity.policycategories.id | Number | ID of the category. | 
| UmbrellaReporting.Activity.policycategories.label | String | The human readable label of the category. | 
| UmbrellaReporting.Activity.policycategories.type | String | Type of the request. A DNS request always has type dns. | 
| UmbrellaReporting.Activity.policycategories.deprecated | Boolean | Whether the category is a legacy category. | 
| UmbrellaReporting.Activity.policycategories.integration | Boolean | Whether the category is an integration. | 
| UmbrellaReporting.Activity.categories.id | Number | ID of the category. | 
| UmbrellaReporting.Activity.categories.label | String | The human readable label of the category. | 
| UmbrellaReporting.Activity.categories.type | String | The type of category. | 
| UmbrellaReporting.Activity.categories.deprecated | Boolean | Whether the category is a legacy category. | 
| UmbrellaReporting.Activity.categories.integration | Boolean | Whether the category is an integration. | 
| UmbrellaReporting.Activity.verdict | String | Verdict for entry. | 
| UmbrellaReporting.Activity.domain | String | Domain for entry. | 
| UmbrellaReporting.Activity.timestamp | Number | Timestamp in ms. | 
| UmbrellaReporting.Activity.time | String | The time in 24 hour format based on the time zone parameter. | 
| UmbrellaReporting.Activity.date | String | The date from the timestamp based on the time zone parameter. | 
| UmbrellaReporting.Activity.identities.id | Number | ID of the identity. | 
| UmbrellaReporting.Activity.identities.type.id | Number | Origin type for the identity. | 
| UmbrellaReporting.Activity.identities.type.type | String | Origin type name for the identity. | 
| UmbrellaReporting.Activity.identities.type.label | String | Origin type label for the identity. | 
| UmbrellaReporting.Activity.identities.label | String | Label for the identity. | 
| UmbrellaReporting.Activity.identities.deleted | Boolean | Indicates whether the identity was deleted. | 
| UmbrellaReporting.Activity.threats.label | Boolean | The threat name or label. | 
| UmbrellaReporting.Activity.threats.type | String | The type of threat. | 
| UmbrellaReporting.Activity.allapplications.id | Number | ID of the application. | 
| UmbrellaReporting.Activity.allapplications.type | String | Type of the application, NBAR or AVC. | 
| UmbrellaReporting.Activity.allapplications.label | String | Label of the application. | 
| UmbrellaReporting.Activity.allapplications.category.label | String | Label of the application category. | 
| UmbrellaReporting.Activity.allapplications.category.id | Number | ID of the application category. | 
| UmbrellaReporting.Activity.allowedapplications.id | Number | ID of the application. | 
| UmbrellaReporting.Activity.allowedapplications.label | String | Label of the application. | 
| UmbrellaReporting.Activity.allowedapplications.type | String | Type of the application, NBAR or AVC. | 
| UmbrellaReporting.Activity.allowedapplications.category.label | String | Label of the application category. | 
| UmbrellaReporting.Activity.allowedapplications.category.id | Number | ID of the application category. | 
| UmbrellaReporting.Activity.querytype | String | The type of DNS request that was made. For more information, see Common DNS Request Types. https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella- | 
| UmbrellaReporting.Activity.returncode | Number | The DNS return code for this request. For more information, see Common DNS return codes for any DNS service \(and Umbrella\). https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella- | 
| UmbrellaReporting.Activity.blockedapplications.id | Number | ID of the application. | 
| UmbrellaReporting.Activity.blockedapplications.label | String | Label of the application. | 
| UmbrellaReporting.Activity.blockedapplications.type | String | Type of the application, NBAR or AVC. | 
| UmbrellaReporting.Activity.blockedapplications.category.label | String | Label of the application category. | 
| UmbrellaReporting.Activity.blockedapplications.category.id | Number | ID of the application category. | 

#### Command example
```!umbrella-reporting-activity-list limit=2```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "Activity": [
            {
                "allapplications": [
                    {
                        "category": {
                            "id": 46,
                            "label": "Ad Publishing"
                        },
                        "id": 46102,
                        "label": "Google Marketing Platform"
                    }
                ],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": false,
                        "id": 27,
                        "integration": false,
                        "label": "Advertisements",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 148,
                        "integration": false,
                        "label": "Application",
                        "type": "application"
                    }
                ],
                "date": "2022-10-29",
                "device": {
                    "id": null
                },
                "domain": "dummy.domain.com",
                "externalip": "4.4.4.4",
                "identities": [
                    {
                        "deleted": false,
                        "id": 593805843,
                        "label": "S\u2019s MacBook Pro",
                        "type": {
                            "id": 9,
                            "label": "Roaming Computers",
                            "type": "roaming"
                        }
                    }
                ],
                "internalip": "1.1.1.1",
                "policycategories": [],
                "querytype": "A",
                "returncode": 0,
                "threats": [],
                "time": "07:39:08",
                "timestamp": 1667029148000,
                "type": "dns",
                "verdict": "allowed"
            },
            {
                "allapplications": [
                    {
                        "category": {
                            "id": null,
                            "label": "Sample Application Group"
                        },
                        "id": 28,
                        "label": "Do Not Decrypt Application"
                    }
                ],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": true,
                        "id": 25,
                        "integration": false,
                        "label": "abc/efgh",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 123,
                        "integration": false,
                        "label": "Infrastructure and Content Delivery Networks",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 148,
                        "integration": false,
                        "label": "Application",
                        "type": "application"
                    }
                ],
                "date": "2022-10-29",
                "device": {
                    "id": null
                },
                "domain": "dummy.domain.com",
                "externalip": "4.4.4.4",
                "identities": [
                    {
                        "deleted": false,
                        "id": 593805843,
                        "label": "S\u2019s MacBook Pro",
                        "type": {
                            "id": 9,
                            "label": "Roaming Computers",
                            "type": "roaming"
                        }
                    }
                ],
                "internalip": "1.1.1.1",
                "policycategories": [],
                "querytype": "AAAA",
                "returncode": 0,
                "threats": [],
                "time": "07:38:57",
                "timestamp": 1667029137000,
                "type": "dns",
                "verdict": "allowed"
            }
        ]
    }
}
```

#### Human Readable Output

>### Activity List
>|Request|Identity|Policy or Ruleset Identity|Destination|Internal IP|External IP|DNS Type|Action|Categories|Public Application|Application Category|Date & Time|
>|---|---|---|--|---|---|---|---|---|---|---|---|
>| dns | S’s MacBook Pro | S’s MacBook Pro | stats.g.doubleclick.net | 1.1.1.1 | 4.4.4.4 | A | allowed | Advertisements, Application | Google Marketing Platform | Ad Publishing | 2022-10-29T07:39:08Z |
>| dns | S’s MacBook Pro | S’s MacBook Pro | google.com | 1.1.1.1 | 4.4.4.4 | AAAA | allowed | abc/efgh, Infrastructure and Content Delivery Networks, Application | Do Not Decrypt Application | Sample Application Group | 2022-10-29T07:38:57Z |


### umbrella-reporting-activity-get

***
List all entries within a time frame based on the traffic type selected. Valid activity types are dns, proxy, firewall, intrusion, ip, amp.
Only one activity type can be selected at a time.

#### Base Command

`umbrella-reporting-activity-get`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| traffic_type | Specify the type of traffic.  By default, all supported traffic types are included. Possible values are: **`dns`**, **`proxy`**, **`firewall`**, **`ip`**, **`intrusion`**, **`amp`**.<br/><br/> Supported optional parameters for **`DNS`** traffic type are **`limit`**, **`from`**,  **`to`**, **`offset`**, **`domains`**, **`ip`**, **`verdict`**, **`threats`**, **`threat_types`**.<br/><br/>Supported optional parameters for **`Proxy`** traffic type are **`limit`**, **`from`**, **`to`**, **`offset`**, **`domains`**, **`ip`**, **`verdict`**, **`threats`**, **`threat_types`**, **`urls`**, **`ports`**, **`identity_types`**, **`file_name`**, **`amp_disposition`**.<br/><br/>Supported optional parameters for **`Firewall`** traffic type are **`limit`**, **`from`**, **`to`**, **`offset`**, **`ip`**, **`ports`**, **`verdict`**.<br/><br/>Supported optional parameters for **`Intrusion`** traffic type are **`limit`**, **`from`**, **`to`**, **`offset`**, **`ip`**, **`ports`**, **`signatures`**, **`intrusion_action`**.<br/><br/>Supported optional parameters for **`IP`** traffic type are **`limit`**, **`from`**, **`to`**, **`offset`**, **`ip`**, **`ports`**, **`identity_types`**, **`verdict`**.<br/><br/>Supported optional parameters for **`Advanced Malware Protection (AMP)`** traffic type are **`limit`**, **`from`**, **`to`**, **`offset`**, **`amp_disposition`**, **`sha256`**.| Required | 
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user then the limit argument will be ignored.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional | 
| domains | A domain name or comma-separated list of domain names.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional | 
| urls | A URL or comma-separated list of URLs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional | 
| ip | An IP address.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Optional | 
| ports | A port number or comma-separated list of port numbers.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional | 
| identity_types | An identity type or comma-separated list of identity types.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional | 
| file_name | A string that identifies a filename. Filter the request by the filename. Supports globbing or use of the wildcard character (''). The asterisk (*) matches zero or more occurrences of any character.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Optional | 
| threats | A threat name or comma-separated list of threat names.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional | 
| threat_types | A threat type or comma-separated list of threat types.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional | 
| amp_disposition | An Advanced Malware Protection (AMP) disposition string. Possible values are: clean, malicious, unknown.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Optional | 
| page | The page number. Default is 1.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Optional | 
| page_size | The number of requested results per page. Default is 50.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Optional | 
| signatures | A comma-separated list of Generator id - Signatures ID. Where Generator ID is unique id assigned to the part of the IPS which generated the event and Signature ID is used to uniquely identify signatures. Example:- 1-2,1-4.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Optional | 
| intrusion_action | Comma-separated list of intrusion actions. Possible values: would_block, blocked, detected.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Optional | 
| categories | A comma-separated list of category ids to filter on. | Optional | 


#### Context Output for **`traffic_type = dns`** for base command **`umbrella-reporting-activity-get`**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.ActivityDns.type | String | Type of the request. A DNS request always has type DNS. | 
| UmbrellaReporting.ActivityDns.externalip | String | External IP address for entry. | 
| UmbrellaReporting.ActivityDns.internalip | String | Internal IP address for entry. | 
| UmbrellaReporting.ActivityDns.policycategories.id | Number | ID of the category. | 
| UmbrellaReporting.ActivityDns.policycategories.label | String | The human readable label of the category. | 
| UmbrellaReporting.ActivityDns.policycategories.type | String | Type of the request. A DNS request always has type dns. | 
| UmbrellaReporting.ActivityDns.policycategories.deprecated | Boolean | Whether the category is a legacy category. | 
| UmbrellaReporting.ActivityDns.policycategories.integration | Boolean | Whether the category is an integration. | 
| UmbrellaReporting.ActivityDns.categories.id | Number | ID of the category. | 
| UmbrellaReporting.ActivityDns.categories.label | String | The human readable label of the category. | 
| UmbrellaReporting.ActivityDns.categories.type | String | The type of category. | 
| UmbrellaReporting.ActivityDns.categories.deprecated | Boolean | Whether the category is a legacy category. | 
| UmbrellaReporting.ActivityDns.categories.integration | Boolean | Whether the category is an integration. | 
| UmbrellaReporting.ActivityDns.verdict | String | Verdict for entry. | 
| UmbrellaReporting.ActivityDns.domain | String | Domain for entry. | 
| UmbrellaReporting.ActivityDns.timestamp | Number | Timestamp in ms. | 
| UmbrellaReporting.ActivityDns.time | String | The time in 24 hour format based on the time zone parameter. | 
| UmbrellaReporting.ActivityDns.date | String | The date from the timestamp based on the time zone parameter. | 
| UmbrellaReporting.ActivityDns.identities.id | Number | ID of the identity. | 
| UmbrellaReporting.ActivityDns.identities.type.id | Number | Origin type for the identity. | 
| UmbrellaReporting.ActivityDns.identities.type.type | String | Origin type name for the identity. | 
| UmbrellaReporting.ActivityDns.identities.type.label | String | Origin type label for the identity. | 
| UmbrellaReporting.ActivityDns.identities.label | String | Label for the identity. | 
| UmbrellaReporting.ActivityDns.identities.deleted | Boolean | Indicates whether the identity was deleted. | 
| UmbrellaReporting.ActivityDns.threats.label | Boolean | The threat name or label. | 
| UmbrellaReporting.ActivityDns.threats.type | String | The type of threat. | 
| UmbrellaReporting.ActivityDns.allapplications.id | Number | ID of the application. | 
| UmbrellaReporting.ActivityDns.allapplications.type | String | Type of the application, NBAR or AVC. | 
| UmbrellaReporting.ActivityDns.allapplications.label | String | Label of the application. | 
| UmbrellaReporting.ActivityDns.allapplications.category.label | String | Label of the application category. | 
| UmbrellaReporting.ActivityDns.allapplications.category.id | Number | ID of the application category. | 
| UmbrellaReporting.ActivityDns.allowedapplications.id | Number | ID of the application. | 
| UmbrellaReporting.ActivityDns.allowedapplications.label | String | Label of the application. | 
| UmbrellaReporting.ActivityDns.allowedapplications.type | String | Type of the application, NBAR or AVC. | 
| UmbrellaReporting.ActivityDns.allowedapplications.category.label | String | Label of the application category. | 
| UmbrellaReporting.ActivityDns.allowedapplications.category.id | Number | ID of the application category. | 
| UmbrellaReporting.ActivityDns.querytype | String | The type of DNS request that was made. For more information, see https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella- | 
| UmbrellaReporting.ActivityDns.returncode | Number | The DNS return code for this request. For more information, see Common DNS return codes for any DNS service \(and Umbrella\). https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella- | 
| UmbrellaReporting.ActivityDns.blockedapplications.id | Number | ID of the application. | 
| UmbrellaReporting.ActivityDns.blockedapplications.label | String | Label of the application. | 
| UmbrellaReporting.ActivityDns.blockedapplications.type | String | Type of the application, NBAR or AVC. | 
| UmbrellaReporting.ActivityDns.blockedapplications.category.label | String | Label of the application category. | 
| UmbrellaReporting.ActivityDns.blockedapplications.category.id | Number | ID of the application category. | 

#### Command example for **`traffic_type = dns`** for base command **`umbrella-reporting-activity-get`**
```!umbrella-reporting-activity-get traffic_type=dns limit=2```
#### Context Example for **`traffic_type = dns`** for base command **`umbrella-reporting-activity-get`**
```json
{
    "UmbrellaReporting": {
        "ActivityDns": [
            {
                "allapplications": [
                    {
                        "category": {
                            "id": 46,
                            "label": "Ad Publishing"
                        },
                        "id": 46102,
                        "label": "Google Marketing Platform"
                    }
                ],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": false,
                        "id": 27,
                        "integration": false,
                        "label": "Advertisements",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 148,
                        "integration": false,
                        "label": "Application",
                        "type": "application"
                    }
                ],
                "date": "2022-10-29",
                "device": {
                    "id": null
                },
                "domain": "dummy.domain.com",
                "externalip": "4.4.4.4",
                "identities": [
                    {
                        "deleted": false,
                        "id": 593805843,
                        "label": "S\u2019s MacBook Pro",
                        "type": {
                            "id": 9,
                            "label": "Roaming Computers",
                            "type": "roaming"
                        }
                    }
                ],
                "internalip": "1.1.1.1",
                "policycategories": [],
                "querytype": "A",
                "returncode": 0,
                "threats": [],
                "time": "07:39:08",
                "timestamp": 1667029148000,
                "type": "dns",
                "verdict": "allowed"
            },
            {
                "allapplications": [
                    {
                        "category": {
                            "id": null,
                            "label": "Sample Application Group"
                        },
                        "id": 28,
                        "label": "Do Not Decrypt Application"
                    }
                ],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": true,
                        "id": 25,
                        "integration": false,
                        "label": "abc/efgh",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 123,
                        "integration": false,
                        "label": "Infrastructure and Content Delivery Networks",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 148,
                        "integration": false,
                        "label": "Application",
                        "type": "application"
                    }
                ],
                "date": "2022-10-29",
                "device": {
                    "id": null
                },
                "domain": "dummy.domain.com",
                "externalip": "4.4.4.4",
                "identities": [
                    {
                        "deleted": false,
                        "id": 593805843,
                        "label": "S\u2019s MacBook Pro",
                        "type": {
                            "id": 9,
                            "label": "Roaming Computers",
                            "type": "roaming"
                        }
                    }
                ],
                "internalip": "1.1.1.1",
                "policycategories": [],
                "querytype": "AAAA",
                "returncode": 0,
                "threats": [],
                "time": "07:38:57",
                "timestamp": 1667029137000,
                "type": "dns",
                "verdict": "allowed"
            }
        ]
    }
}
```

#### Human Readable Output

>### Dns Activity List
>|Identity|Policy or Ruleset Identity|Destination|Internal IP|External IP|DNS Type|Action|Categories|Public Application|Application Category|Date & Time|
>|---|---|---|---|---|---|---|---|---|---|---|
>| S’s MacBook Pro | S’s MacBook Pro | stats.g.doubleclick.net | 1.1.1.1 | 4.4.4.4 | A | allowed | Advertisements, Application | Google Marketing Platform | Ad Publishing | 2022-10-29T07:39:08Z |
>| S’s MacBook Pro | S’s MacBook Pro | google.com | 1.1.1.1 | 4.4.4.4 | AAAA | allowed | abc/efgh, Infrastructure and Content Delivery Networks, Application | Do Not Decrypt Application | Sample Application Group | 2022-10-29T07:38:57Z |


#### Context Output for **`traffic_type = amp`** for base command **`umbrella-reporting-activity-get`**

| **Path**                                            | **Type** | **Description** |
|-----------------------------------------------------| --- |-----------|
| UmbrellaReporting.ActivityAMPRetro.timestamp              | Number | Timestamp in ms. | 
| UmbrellaReporting.ActivityAMPRetro.firstseenat              | Number | First seen Timestamp. |
| UmbrellaReporting.ActivityAMPRetro.disposition              | String | Disposition for entry. |
| UmbrellaReporting.ActivityAMPRetro.hostname              | String | Hostname for entry. |
| UmbrellaReporting.ActivityAMPRetro.malwarename              | String | Malware name for entry. |
| UmbrellaReporting.ActivityAMPRetro.sha256              | String | SHA256 for entry. |
| UmbrellaReporting.ActivityAMPRetro.score              | Number | Score for entry. |


#### Command example for **`traffic_type = amp`** for base command **`umbrella-reporting-activity-get`**
```!umbrella-reporting-activity-get traffic_type=amp limit=2```

#### Context Example for **`traffic_type = amp`** for base command **`umbrella-reporting-activity-get`**
```json
{
   "UmbrellaReporting":{
      "ActivityAMPRetro":[
        {
            "timestamp": 1548311506,
            "firstseenat": 1548311506,
            "disposition": "clean",
            "score": 10,
            "hostname": "google.com",
            "malwarename": "malware",
            "sha256": "dummy_sha256"
        }
    ]
   }
}
```
#### Human Readable Output

>### AMP Activity List
>|First Seen| Disposition | Score | Host Name | Malware | SHA256 | Date & Time |
>|---|---|---|---|--------|---|---|
>| 1548311506 | clean | 10 | google.com | malware | 9495b6c155044053953efe30ebaf804780c114e7b721b14f6a5b0a782769696e | Sep 16, 2022 05:52 AM |

#### Context Output for **`traffic_type = proxy`** for base command **`umbrella-reporting-activity-get`**

| **Path**                                                         | **Type** | **Description**                                            |
|------------------------------------------------------------------|----------|------------------------------------------------------------|
| UmbrellaReporting.ActivityProxy.type                             | String | Type of the request. A Proxy request always has type Proxy.| 
| UmbrellaReporting.ActivityProxy.externalip                         | String   | External IP for entry.                                     | 
| UmbrellaReporting.ActivityProxy.destinationip                         | String   | Destination IP for entry.                                  |
| UmbrellaReporting.ActivityProxy.blockedfiletype                         | String   | locked file type for entry.                                | 
| UmbrellaReporting.ActivityProxy.contenttype                         | String   | The type of web content, typically text/html.              |
| UmbrellaReporting.ActivityProxy.forwardingmethod                         | String   | The request method (GET, POST, HEAD, etc.)                 |
| UmbrellaReporting.ActivityProxy.internalip                         | String   | Internal IP for entry.                                     |
| UmbrellaReporting.ActivityProxy.referer                         | String   | The referring domain or URL.                               |
| UmbrellaReporting.ActivityProxy.requestmethod                         | String   | The HTTP request method that was made.                     |
| UmbrellaReporting.ActivityProxy.responsefilename                         | String   | Response filename for entry.                               |
| UmbrellaReporting.ActivityProxy.sha256                         | String   | The hex digest of the response content.                    |
| UmbrellaReporting.ActivityProxy.url                         | String   | The URL requested.                                         |
| UmbrellaReporting.ActivityProxy.useragent                         | String   | The browser agent that made the request.                   |
| UmbrellaReporting.ActivityProxy.warnstatus                         | String   | Warn Status.                                               |
| UmbrellaReporting.ActivityProxy.securityoverridden                         | Boolean  | Specify whether to filter on requests that override security.                                       |
| UmbrellaReporting.ActivityProxy.tenantcontrols                         | Boolean  | If the request was part of a tenant control policy.        |
| UmbrellaReporting.ActivityProxy.bundleid                     | Number   | A proxy bundle ID.                                                  |
| UmbrellaReporting.ActivityProxy.port                     | Number   | Request Port.                                              |
| UmbrellaReporting.ActivityProxy.requestsize                     | Number   | Request size in bytes.                                     |
| UmbrellaReporting.ActivityProxy.responsesize                     | Number   | Response size in bytes.                                    |
| UmbrellaReporting.ActivityProxy.statuscode                     | Number   | The HTTP status code; should always be 200 or 201.         |
| UmbrellaReporting.ActivityProxy.policycategories.id                | Number   | ID of category.                                            | 
| UmbrellaReporting.ActivityProxy.policycategories.label             | String   | The human readable label of the category.                  | 
| UmbrellaReporting.ActivityProxy.policycategories.type              | String   | Type of the request. a dns request always has type dns.    | 
| UmbrellaReporting.ActivityProxy.policycategories.deprecated        | Boolean  | If the category is a legacy category.                      | 
| UmbrellaReporting.ActivityProxy.policycategories.integration       | Boolean  | If the category is an integration.                         | 
| UmbrellaReporting.ActivityProxy.categories.id                      | Number   | id of category                                             | 
| UmbrellaReporting.ActivityProxy.categories.label                   | String   | The human readable label of the category                   | 
| UmbrellaReporting.ActivityProxy.categories.type                    | String   | The type of category                                       | 
| UmbrellaReporting.ActivityProxy.categories.deprecated              | Boolean  | If the category is a legacy category                       | 
| UmbrellaReporting.ActivityProxy.categories.integration             | Boolean  | If the category is an integration                          | 
| UmbrellaReporting.ActivityProxy.antivirusthreats.others                     | Unknown  | Other antivirus threats.                                   | 
| UmbrellaReporting.ActivityProxy.antivirusthreats.puas                   | Unknown  | Potentially unwanted applications.                         | 
| UmbrellaReporting.ActivityProxy.antivirusthreats.viruses                    | Unknown  | Viruses.                                                   |  
| UmbrellaReporting.ActivityProxy.verdict                            | String   | Verdict for entry.                                         | 
| UmbrellaReporting.ActivityProxy.timestamp                          | Number   | Timestamp in ms.                                           | 
| UmbrellaReporting.ActivityProxy.time                               | String   | The time in 24 hour format based on the timezone parameter. | 
| UmbrellaReporting.ActivityProxy.date                               | String   | The date from the timestamp based on the timezone parameter. | 
| UmbrellaReporting.ActivityProxy.identities.id                      | Number   | ID of identity.                                            | 
| UmbrellaReporting.ActivityProxy.identities.type.id                 | Number   | Origin type for identity                                   | 
| UmbrellaReporting.ActivityProxy.identities.type.type               | String   | Origin type name for identity                              | 
| UmbrellaReporting.ActivityProxy.identities.type.label              | String   | Origin type label for identity                             | 
| UmbrellaReporting.ActivityProxy.identities.label                   | String   | Label for identity                                         | 
| UmbrellaReporting.ActivityProxy.identities.deleted                 | Boolean  | Indicates whether the identity was deleted or not          | 
| UmbrellaReporting.ActivityProxy.threats.label                      | String   | The threat name or label.                                  | 
| UmbrellaReporting.ActivityProxy.threats.type                       | String   | The type of threat.                                        | 
| UmbrellaReporting.ActivityProxy.datacenter.id             | String   | Unique ID for the data center.                             | 
| UmbrellaReporting.ActivityProxy.datacenter.label          | String   | Name of the data center.                                   | 
| UmbrellaReporting.ActivityProxy.datalossprevention.state          | String   | If the request was Blocked for DLP. Either 'blocked' or ''. |
| UmbrellaReporting.ActivityProxy.egress.ip             | String   | Egress IP.                                                 | 
| UmbrellaReporting.ActivityProxy.egress.type          | String   | Egress Type.                                               |
| UmbrellaReporting.ActivityProxy.isolated.fileaction             | String   | A string that describes the remote browser isolation (RBI) file action type.                                        | 
| UmbrellaReporting.ActivityProxy.isolated.state          | String   |  A string that describes the remote browser isolation(RBI) isolation type.                                            |
| UmbrellaReporting.ActivityProxy.allapplications.id                 | Number   | ID of the application.                                     | 
| UmbrellaReporting.ActivityProxy.allapplications.type               | String   | Type of the application, NBAR or AVC.                      | 
| UmbrellaReporting.ActivityProxy.allapplications.label              | String   | Label of the application.                                  | 
| UmbrellaReporting.ActivityProxy.allapplications.category.label     | String   | Label of the application category.                         | 
| UmbrellaReporting.ActivityProxy.allapplications.category.id        | Number   | ID of the application category.                            | 
| UmbrellaReporting.ActivityProxy.allowedapplications.id             | Number   | ID of the application.                                     | 
| UmbrellaReporting.ActivityProxy.allowedapplications.label          | String   | Label of the application.                                  | 
| UmbrellaReporting.ActivityProxy.allowedapplications.type           | String   | Type of the application, NBAR or AVC.                      | 
| UmbrellaReporting.ActivityProxy.allowedapplications.category.label | String   | Label of the application category.                         | 
| UmbrellaReporting.ActivityProxy.allowedapplications.category.id    | Number   | ID of the application category.                            | 
| UmbrellaReporting.ActivityProxy.blockedapplications.id             | Number   | ID of the application.                                     | 
| UmbrellaReporting.ActivityProxy.blockedapplications.label          | String   | Label of the application.                                  | 
| UmbrellaReporting.ActivityProxy.blockedapplications.type           | String   | Type of the application, NBAR or AVC.                      | 
| UmbrellaReporting.ActivityProxy.blockedapplications.category.label | String   | Label of the application category.                         | 
| UmbrellaReporting.ActivityProxy.blockedapplications.category.id | Number   | Label of the application category.                         | 
| UmbrellaReporting.ActivityProxy.policy.timebasedrule                | Boolean  | Whether the policy triggered a time-of-day rule.           | 
| UmbrellaReporting.ActivityProxy.policy.ruleid               | Number   | The rule ID for the policy.                                | 
| UmbrellaReporting.ActivityProxy.policy.rulesetid           | Number   | The rule set ID for the policy.                            |  
| UmbrellaReporting.ActivityProxy.policy.destinationlistids                 | Unknown  | The destination lists that the policy triggered.           | 
| UmbrellaReporting.ActivityProxy.httperrors.reason                | String   | The name of the error.                                     | 
| UmbrellaReporting.ActivityProxy.httperrors.type               | String   | Type of the error CertificateError or TLSError.            | 
| UmbrellaReporting.ActivityProxy.httperrors.attributes           | Unknown  | Map of additional information about the error.             |  
| UmbrellaReporting.ActivityProxy.httperrors.code                 | String   | The http error code.                                       |
| UmbrellaReporting.ActivityProxy.amp.disposition               | String   | Advanced Malware Protection (AMP) disposition.                                           | 
| UmbrellaReporting.ActivityProxy.amp.malware           | String   | Advanced Malware Protection (AMP) malware.                                               |  
| UmbrellaReporting.ActivityProxy.amp.score                 | Number   | Advanced Malware Protection (AMP) score.                                                 |

#### Command example for **`traffic_type = proxy`** for base command **`umbrella-reporting-activity-get`**
```!umbrella-reporting-activity-get traffic_type=proxy limit=2```
#### Context Example for **`traffic_type = proxy`** for base command **`umbrella-reporting-activity-get`**
```json
{
    "UmbrellaReporting": {
        "ActivityProxy": [
            {
                "allapplications": [],
                "allowedapplications": [],
                "amp": {
                    "disposition": "",
                    "malware": "",
                    "score": 0
                },
                "antivirusthreats": {
                    "others": [],
                    "puas": [],
                    "viruses": []
                },
                "blockedapplications": [],
                "blockedfiletype": "",
                "bundleid": 13531789,
                "categories": [
                    {
                        "deprecated": false,
                        "id": 123,
                        "integration": false,
                        "label": "Infrastructure and Content Delivery Networks",
                        "type": "content"
                    }
                ],
                "contenttype": "application/pkix-crl",
                "datacenter": {
                    "id": "",
                    "label": ""
                },
                "datalossprevention": {
                    "state": ""
                },
                "date": "2022-10-17",
                "destinationip": "1.1.1.1",
                "egress": {
                    "ip": "",
                    "type": ""
                },
                "externalip": "4.4.4.4",
                "forwardingmethod": "",
                "httperrors": [],
                "identities": [
                    {
                        "deleted": false,
                        "id": 589064228,
                        "label": "DESKTOP-IIQVPJ7",
                        "type": {
                            "id": 9,
                            "label": "Roaming Computers",
                            "type": "roaming"
                        }
                    }
                ],
                "internalip": "1.1.1.1",
                "isolated": {
                    "fileaction": "",
                    "state": ""
                },
                "policy": {
                    "destinationlistids": [],
                    "ruleid": null,
                    "rulesetid": null,
                    "timebasedrule": false
                },
                "policycategories": [],
                "port": 80,
                "referer": "",
                "requestmethod": "GET",
                "requestsize": 0,
                "responsefilename": " ",
                "responsesize": 0,
                "securityoverridden": false,
                "sha256": "dummy_sha256",
                "statuscode": 304,
                "tenantcontrols": false,
                "threats": [],
                "time": "09:38:32",
                "timestamp": 1665999512000,
                "type": "proxy",
                "url": "http://google.com",
                "useragent": "Microsoft-CryptoAPI/10.0",
                "verdict": "allowed",
                "warnstatus": ""
            },
            {
                "allapplications": [],
                "allowedapplications": [],
                "amp": {
                    "disposition": "",
                    "malware": "",
                    "score": 0
                },
                "antivirusthreats": {
                    "others": [],
                    "puas": [],
                    "viruses": []
                },
                "blockedapplications": [],
                "blockedfiletype": "",
                "bundleid": 13531789,
                "categories": [
                    {
                        "deprecated": false,
                        "id": 123,
                        "integration": false,
                        "label": "Infrastructure and Content Delivery Networks",
                        "type": "content"
                    }
                ],
                "contenttype": "application/pkix-crl",
                "datacenter": {
                    "id": "",
                    "label": ""
                },
                "datalossprevention": {
                    "state": ""
                },
                "date": "2022-10-17",
                "destinationip": "1.1.1.1",
                "egress": {
                    "ip": "",
                    "type": ""
                },
                "externalip": "4.4.4.4",
                "forwardingmethod": "",
                "httperrors": [],
                "identities": [
                    {
                        "deleted": false,
                        "id": 589064228,
                        "label": "DESKTOP-IIQVPJ7",
                        "type": {
                            "id": 9,
                            "label": "Roaming Computers",
                            "type": "roaming"
                        }
                    }
                ],
                "internalip": "1.1.1.1",
                "isolated": {
                    "fileaction": "",
                    "state": ""
                },
                "policy": {
                    "destinationlistids": [],
                    "ruleid": null,
                    "rulesetid": null,
                    "timebasedrule": false
                },
                "policycategories": [],
                "port": 80,
                "referer": "",
                "requestmethod": "GET",
                "requestsize": 0,
                "responsefilename": " ",
                "responsesize": 0,
                "securityoverridden": false,
                "sha256": "dummy_sha256",
                "statuscode": 304,
                "tenantcontrols": false,
                "threats": [],
                "time": "08:36:16",
                "timestamp": 1665995776000,
                "type": "proxy",
                "url": "google.com",
                "useragent": "Microsoft-CryptoAPI/10.0",
                "verdict": "allowed",
                "warnstatus": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Proxy Activity List
>|Identity|Policy or Ruleset Identity|Internal IP|External IP|Action|Categories|Date & Time|
>|---|---|---|---|---|---|---|
>| DESKTOP-IIQVPJ7 | DESKTOP-IIQVPJ7 | 10.10.10.217 | 4.4.4.4 | allowed | Infrastructure and Content Delivery Networks | 2022-10-17T09:38:32Z |
>| DESKTOP-IIQVPJ7 | DESKTOP-IIQVPJ7 | 10.10.10.217 | 4.4.4.4 | allowed | Infrastructure and Content Delivery Networks | 2022-10-17T08:36:16Z |


#### Context Output for **`traffic_type = firewall`** for base command **`umbrella-reporting-activity-get`**

| **Path**                                                         | **Type** | **Description** |
|------------------------------------------------------------------| --- |-----------|
| UmbrellaReporting.ActivityFirewall.type                             | String | Type of the request. A Firewall request always has type Firewall. | 
| UmbrellaReporting.ActivityFirewall.destinationip                      | String | Destination IP for entry. |
| UmbrellaReporting.ActivityFirewall.direction                         | String | The direction of the packet. It is destined either towards the internet or to the customer's network. |
| UmbrellaReporting.ActivityFirewall.sourceip                         | String | Source IP for entry. |
| UmbrellaReporting.ActivityFirewall.destinationport                    | Number | Destination port for entry. |
| UmbrellaReporting.ActivityFirewall.sourceport                         | Number | Source port for entry. |
| UmbrellaReporting.ActivityFirewall.packetsize                         | Number | The size of the packet that Umbrella CDFW received. |
| UmbrellaReporting.ActivityFirewall.verdict                            | String | Verdict for entry. | 
| UmbrellaReporting.ActivityFirewall.timestamp                          | Number | Timestamp in ms. | 
| UmbrellaReporting.ActivityFirewall.time                               | String | The time in 24 hour format based on the timezone parameter. | 
| UmbrellaReporting.ActivityFirewall.date                               | String | The date from the timestamp based on the timezone parameter. | 
| UmbrellaReporting.ActivityFirewall.identities.id                      | Number | ID of identity. | 
| UmbrellaReporting.ActivityFirewall.identities.type.id                 | Number | Origin type for identity | 
| UmbrellaReporting.ActivityFirewall.identities.type.type               | String | Origin type name for identity | 
| UmbrellaReporting.ActivityFirewall.identities.type.label              | String | Origin type label for identity | 
| UmbrellaReporting.ActivityFirewall.identities.label                   | String | Label for identity | 
| UmbrellaReporting.ActivityFirewall.identities.deleted                 | Boolean | Indicates whether the identity was deleted or not | 
| UmbrellaReporting.ActivityFirewall.protocol.label                     | String | Name of the protocol. | 
| UmbrellaReporting.ActivityFirewall.protocol.id                       | Number | ID of protocol. | 
| UmbrellaReporting.ActivityFirewall.allapplications.id                 | Number | ID of the application. | 
| UmbrellaReporting.ActivityFirewall.allapplications.app               | String | Type: "IT Service Management" (string) - application/protocol type. | 
| UmbrellaReporting.ActivityFirewall.allapplications.label              | String | Label of the application. | 
| UmbrellaReporting.ActivityFirewall.rule.label                 | String | Name of the rule | 
| UmbrellaReporting.ActivityFirewall.rule.id                      | String | ID of rule. | 
| UmbrellaReporting.ActivityFirewall.rule.privateapplicationgroup.label | String | Name of application group. | 
| UmbrellaReporting.ActivityFirewall.rule.privateapplicationgroup.id    | Number | ID of application group | 
| UmbrellaReporting.ActivityFirewall.applicationprotocols.id            | Number | ID of the application. | 
| UmbrellaReporting.ActivityFirewall.applicationprotocols.app           | String | Type: "IT Service Management" (string) - application/protocol type. | 
| UmbrellaReporting.ActivityFirewall.applicationprotocols.label         | String | Application/Protocol label. |


#### Command example for **`traffic_type = firewall`** for base command **`umbrella-reporting-activity-get`**
```!umbrella-reporting-activity-get traffic_type=firewall limit=2```

#### Context Example for **`traffic_type = firewall`** for base command **`umbrella-reporting-activity-get`**
```json
{
   "UmbrellaReporting":{
      "ActivityFirewall":[
        {
            "date": "2019",
            "destinationip": "1.1.1.1",
            "sourceip": "192.168.0.1",
            "sourceport": 0,
            "destinationport": 0,
            "verdict": "allowed",
            "time": "12:34",
            "timestamp": 1548311506,
            "identities": [
                {
                    "id": 1,
                    "label": "Catch Rate Testing System",
                    "type": {
                        "id": 21,
                        "label": "Sites",
                        "type": "site"
                    },
                    "deleted": false
                }
            ],
            "protocol": {
                "id": 17,
                "label": "UDP"
            },
            "rule": {
                "id": 1,
                "label": "Default Rule"
            },
            "type": "firewall",
            "allapplications": [
                {
                    "id": 72,
                    "label": "dns IT Service Management",
                    "app": ""
                }
            ],
            "applicationprotocols": [
                {
                    "id": 72,
                    "label": "dns IT Service Management",
                    "app": ""
                }
            ],
            "packetsize": 32,
            "direction": "towards"
        }
    ]
   }
}
```
#### Human Readable Output

>### Firewall Activity List
>|Identity|Policy or Ruleset Identity|Internal IP|Source IP|Source Port|Destination Port|Protocol|Rule|Type|Action|Public Application|Direction|Date & Time|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Catch Rate Testing System | Catch Rate Testing System | 1.1.1.1 | 192.168.0.1 | 0 | 0 | UDP | Default Rule | firewall |allowed|dns IT Service Management|towards| Sep 16, 2022 05:52 AM |


#### Context Output for **`traffic_type = intrusion`** for base command **`umbrella-reporting-activity-get`**

| **Path**                                                         | **Type** | **Description** |
|------------------------------------------------------------------| --- |-----------|
| UmbrellaReporting.ActivityIntrusion.type                             | String | Type of the request. A Intrusion request always has type Intrusion. | 
| UmbrellaReporting.ActivityIntrusion.classification                         | String | The category of attack detected by a rule that is part of a more general type of attack class, such as trojan-activity, attempted-user, and unknown. |
| UmbrellaReporting.ActivityIntrusion.destinationip                         | String | Destination IP for entry. |
| UmbrellaReporting.ActivityIntrusion.severity                         | String | The severity level of the rule, such as High, Medium, Low, and Very Low. |
| UmbrellaReporting.ActivityIntrusion.sourceip                         | String | Source IP for entry|
| UmbrellaReporting.ActivityIntrusion.destinationport                         | Number | Destination port for entry. |
| UmbrellaReporting.ActivityIntrusion.sessionid                         | Number | The unique identifier of a session, which is used to group the correlated events between various services. |
| UmbrellaReporting.ActivityIntrusion.sourceport                         | Number | Source port for entry. |
| UmbrellaReporting.ActivityIntrusion.verdict                            | String | Verdict for entry. | 
| UmbrellaReporting.ActivityIntrusion.timestamp                          | Number | Timestamp in ms. | 
| UmbrellaReporting.ActivityIntrusion.time                               | String | The time in 24 hour format based on the timezone parameter. | 
| UmbrellaReporting.ActivityIntrusion.date                               | String | The date from the timestamp based on the timezone parameter. | 
| UmbrellaReporting.ActivityIntrusion.identities.id                      | Number | ID of identity. | 
| UmbrellaReporting.ActivityIntrusion.identities.type.id                 | Number | Origin type for identity | 
| UmbrellaReporting.ActivityIntrusion.identities.type.type               | String | Origin type name for identity | 
| UmbrellaReporting.ActivityIntrusion.identities.type.label              | String | Origin type label for identity | 
| UmbrellaReporting.ActivityIntrusion.identities.label                   | String | Label for identity | 
| UmbrellaReporting.ActivityIntrusion.identities.deleted                 | Boolean | Indicates whether the identity was deleted or not | 
| UmbrellaReporting.ActivityIntrusion.protocol.label                      | String | Name of the protocol. | 
| UmbrellaReporting.ActivityIntrusion.protocol.id                       | Number | ID of protocol. | 
| UmbrellaReporting.ActivityIntrusion.signature.id                 | Number | ID of the application. | 
| UmbrellaReporting.ActivityIntrusion.signature.generatorid               | Number | Unique id assigned to the part of the IPS which generated the event. | 
| UmbrellaReporting.ActivityIntrusion.signature.label              | String | A brief description of the signature. | 
| UmbrellaReporting.ActivityIntrusion.signature.cves              | String | An identifier for a known security vulnerability/exposure. |
| UmbrellaReporting.ActivityIntrusion.signaturelist.id                 | Number | Unique id assigned to a Default or Custom Signature List. |

#### Command example for **`traffic_type = intrusion`** for base command **`umbrella-reporting-activity-get`**
```!umbrella-reporting-activity-get traffic_type=intrusion limit=2```

#### Context Example for **`traffic_type = intrusion`** for base command **`umbrella-reporting-activity-get`**

```json
{
   "UmbrellaReporting":{
      "ActivityIntrusion":[
        {
            "type": "intrusion",
            "date": "12-02-22",
            "destinationip": "10.10.10.10",
            "protocol": {
                "id": 17,
                "label": "UDP"
            },
            "sourceip": "10.10.10.10",
            "signaturelist": { "id": 1111 },
            "classification": "malicious",
            "sourceport": 22,
            "sessionid": 190898098,
            "verdict": "detected",
            "destinationport": 33,
            "timestamp": 1594557262000,
            "time": "09:30",
            "identities": [
                {
                    "id": 211034846,
                    "type": {
                        "id": 34,
                        "type": "anyconnect",
                        "label": "Anyconnect Roaming Client"
                    },
                    "label": "omerta",
                    "deleted": false
                }
            ],
            "severity": "HIGH",
            "signature": {
                "generatorid": 1,
                "id": 47829,
                "label": "SERVER-OTHER JBoss Richfaces expression language injection attempt",
                "cves": [
                    "cve-2015-0279",
                    "cve-2018-12532"
                ]
            }
        }
    ]
   }
}
```
#### Context Output for **`traffic_type = ip`** for base command **`umbrella-reporting-activity-get`**

| **Path**                                                         | **Type** | **Description** |
|------------------------------------------------------------------| --- |-----------|
| UmbrellaReporting.ActivityIP.type                             | String | Type of the request. A IP request always has type IP. | 
| UmbrellaReporting.ActivityIP.destinationip                         | String | Destination IP for entry. |
| UmbrellaReporting.ActivityIP.sourceip                         | String | Source IP for entry |
| UmbrellaReporting.ActivityIP.destinationport                         | Number | Destination port for entry. |
| UmbrellaReporting.ActivityIP.sourceport                         | Number | Source port for entry. |
| UmbrellaReporting.ActivityIP.verdict                            | String | Verdict for entry. | 
| UmbrellaReporting.ActivityIP.timestamp                          | Number | Timestamp in ms. | 
| UmbrellaReporting.ActivityIP.time                               | String | The time in 24 hour format based on the timezone parameter. | 
| UmbrellaReporting.ActivityIP.date                               | String | The date from the timestamp based on the timezone parameter. | 
| UmbrellaReporting.ActivityIP.identities.id                      | Number | ID of identity. | 
| UmbrellaReporting.ActivityIP.identities.type.id                 | Number | Origin type for identity | 
| UmbrellaReporting.ActivityIP.identities.type.type               | String | Origin type name for identity | 
| UmbrellaReporting.ActivityIP.identities.type.label              | String | Origin type label for identity | 
| UmbrellaReporting.ActivityIP.identities.label                   | String | Label for identity | 
| UmbrellaReporting.ActivityIP.identities.deleted                 | Boolean | Indicates whether the identity was deleted or not | 
| UmbrellaReporting.ActivityIP.categories.id                      | Number | id of category | 
| UmbrellaReporting.ActivityIP.categories.label                   | String | The human readable label of the category | 
| UmbrellaReporting.ActivityIP.categories.type                    | String | The type of category | 
| UmbrellaReporting.ActivityIP.categories.deprecated              | Boolean | If the category is a legacy category | 
| UmbrellaReporting.ActivityIP.categories.integration             | Boolean | If the category is an integration |
#### Command example
```!umbrella-reporting-activity-get traffic_type=ip limit=2```

#### Context Example for **`traffic_type = ip`** for base command **`umbrella-reporting-activity-get`**

```json
{
   "UmbrellaReporting":{
      "ActivityIP":[
        {
            "destinationip": "1.1.1.1",
            "sourceip": "192.168.0.1",
            "date": "03-15-22",
            "sourceport": 0,
            "destinationport": 0,
            "verdict": "allowed",
            "timestamp": 1548311506,
            "time": "10:15",
            "identities": [
                {
                    "id": 1,
                    "label": "Catch Rate Testing System",
                    "type": {
                        "id": 21,
                        "label": "Sites",
                        "type": "site"
                    },
                    "deleted": false
                }
            ],
            "categories": [
                {
                    "id": 66,
                    "label": "Malware",
                    "type": "security",
                    "integration": true
                }
            ],
            "type": "ip"
        }
    ]
   }
}
```
#### Human Readable Output

>### IP Activity List
>|Identity|Destination IP|Source IP|Source Port| Destination Port|Categories|Type|Action|Date & Time|
>|---|---|---|---|---|---|---|---|---|
>| Catch Rate Testing System |  10.10.10.10 | 10.10.10.10 |22|33|Malware|IP|allowed|Sep 16, 2022 05:52 AM|


### umbrella-reporting-summary-list

***
Get the summary.

#### Base Command

`umbrella-reporting-summary-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| summary_type | Get summary list of different summary types. Valid values for summary_type are **`category`**, **`destination`**, **`intrusion_rule`**.<br/>If summary type is not provided by the user, then all summary types i.e., category, destination, intrusion_rule will be considered.<br/><br/>Supported optional parameters for **`category`** summary type are **`domain`**, **`urls`**, **`ip`**, **`identity_types`**, **`verdict`**, **`file_name`**, **`threats`**, **`threat_types`**, **`amp_disposition`**.<br/><br/>Supported optional parameters for **`destination`** summary type are **`domain`**, **`urls`**, **`ip`**, **`identity_types`**, **`verdict`**, **`file_name`**, **`threats`**, **`threat_types`**, **`amp_disposition`**.<br/><br/>Supported optional parameters for **`intrusion_rule`** summary type are **`signatures`**, **`ip`**, **`identity_types`**, **`intrusion_action`**, **`ports`**. | Optional | 
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| limit | The maximum number of records to return from the collection. Limit default value is 50. If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| urls | A URL or comma-separated list of URLs. | Optional | 
| ip | An IP address. | Optional | 
| ports | A port number or comma-separated list of port numbers. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| file_name | A string that identifies a filename. Filter the request by the filename. Supports globbing or use of the wildcard character (''). The asterisk (*) matches zero or more occurrences of any character. | Optional | 
| threats | A threat name or comma-separated list of threat names. | Optional | 
| threat_types | A threat type or comma-separated list of threat types. | Optional | 
| amp_disposition | An Advanced Malware Protection (AMP) disposition string. Possible values are: clean, malicious, unknown. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| signatures | A comma-separated list of Generator id - Signatures ID. Where Generator ID is unique id assigned to the part of the IPS which generated the event and Signature ID is used to uniquely identify signatures. Example:- 1-2,1-4. | Optional | 
| intrusion_action | Comma-separated List of intrusion actions. Possible values: would_block, blocked, detected. | Optional | 
| categories | A comma-separated list of category ids to filter on. | Optional | 


#### Context Output for `summary` for base command `umbrella-reporting-summary-list`

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.Summary.applications | Number | Total number of applications \(avc or total\). | 
| UmbrellaReporting.Summary.applicationsallowed | Number | Total number of allowed applications. | 
| UmbrellaReporting.Summary.applicationsblocked | Number | Total number of blocked applications. | 
| UmbrellaReporting.Summary.categories | Number | Total number of categories. | 
| UmbrellaReporting.Summary.domains | Number | Total number of domains. | 
| UmbrellaReporting.Summary.files | Number | Total number of files. | 
| UmbrellaReporting.Summary.filetypes | Number | Total number of file types. | 
| UmbrellaReporting.Summary.identities | Number | Total number of identities. | 
| UmbrellaReporting.Summary.identitytypes | Number | Total number of identity types. | 
| UmbrellaReporting.Summary.policycategories | Number | Total number of blocked categories. | 
| UmbrellaReporting.Summary.policyrequests | Number | Total number of policy requests. | 
| UmbrellaReporting.Summary.requests | Number | Total number of requests. | 
| UmbrellaReporting.Summary.requestsallowed | Number | Total number of allowed requests. | 
| UmbrellaReporting.Summary.requestsblocked | Number | Total number of blocked requests. | 


#### Command example
```!umbrella-reporting-summary-list domains=api.tunnels.cdfw.umbrella.com```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "Summary": {
            "applications": 0,
            "applicationsallowed": 0,
            "applicationsblocked": 0,
            "categories": 4,
            "domains": 1,
            "files": 0,
            "filetypes": 0,
            "identities": 3,
            "identitytypes": 2,
            "policycategories": 0,
            "policyrequests": 0,
            "requests": 6,
            "requestsallowed": 6,
            "requestsblocked": 0
        }
    }
}
```

#### Human Readable Output

>### Summary List
>|Application|Allowed Application|Blocked Application|Category|Domain|File|File Type|Identity|Identity Type|Policy Category|Policy Request|Request|Allowed Request|Blocked Request|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 0 | 0 | 4 | 1 | 0 | 0 | 3 | 2 | 0 | 0 | 6 | 6 | 0 |


#### Context Output for **`summary_type=category`**  for base command **`umbrella-reporting-summary-list`**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.SummaryWithCategory.category.label | String | The human readable label of the category. | 
| UmbrellaReporting.SummaryWithCategory.category.type | String | The type of category. |
| UmbrellaReporting.SummaryWithCategory.category.deprecated | Boolean | If the category is a legacy category. |
| UmbrellaReporting.SummaryWithCategory.category.integration | boolean | If the category is an integration. |
| UmbrellaReporting.SummaryWithCategory.category.id | Number | ID of category. |
| UmbrellaReporting.SummaryWithCategory.summary.applications | Number | Total number of applications \(avc or total\). | 
| UmbrellaReporting.SummaryWithCategory.summary.applicationsallowed | Number | Total number of allowed applications. | 
| UmbrellaReporting.SummaryWithCategory.summary.applicationsblocked | Number | Total number of blocked applications. | 
| UmbrellaReporting.SummaryWithCategory.summary.categories | Number | Total number of categories. | 
| UmbrellaReporting.SummaryWithCategory.summary.domains | Number | Total number of domains. | 
| UmbrellaReporting.SummaryWithCategory.summary.files | Number | Total number of files. | 
| UmbrellaReporting.SummaryWithCategory.summary.filetypes | Number | Total number of file types. | 
| UmbrellaReporting.SummaryWithCategory.summary.identities | Number | Total number of identities. | 
| UmbrellaReporting.SummaryWithCategory.summary.identitytypes | Number | Total number of identity types. | 
| UmbrellaReporting.SummaryWithCategory.summary.policycategories | Number | Total number of blocked categories. | 
| UmbrellaReporting.SummaryWithCategory.summary.policyrequests | Number | Total number of policy requests. | 
| UmbrellaReporting.SummaryWithCategory.summary.requests | Number | Total number of requests. | 
| UmbrellaReporting.SummaryWithCategory.summary.requestsallowed | Number | Total number of allowed requests. | 
| UmbrellaReporting.SummaryWithCategory.summary.requestsblocked | Number | Total number of blocked requests. |


#### Command example for **`summary_type=category`**  for base command **`umbrella-reporting-summary-list`**
```!umbrella-reporting-summary-list summary_type=category limit=1```

#### Context Example for **`summary_type=category`**  for base command **`umbrella-reporting-summary-list`**
```json
{
   "UmbrellaReporting":{
      "SummaryWithCategory":[
        {
            "category": {
                "id": 66,
                "label": "Malware",
                "type": "security",
                "integration": true
            },
            "summary": {
                "applications": 0,
                "domains": 0,
                "requestsblocked": 0,
                "filetypes": 0,
                "policycategories": 0,
                "requests": 0,
                "requestsallowed": 0,
                "categories": 0,
                "identitytypes": 0,
                "applicationsblocked": 0,
                "files": 0,
                "identities": 0,
                "applicationsallowed": 0,
                "policyrequests": 0
            }
        }
    ]
   }
}
```
#### Human Readable Output

>### Summary with Category List 
>|Category Type| Category Name |Application|Allowed Application|Blocked Application|Category|Domain|File|File Type|Identity|Identity Type|Policy Category|Policy Request|Request|Allowed Request|Blocked Request|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| security | Malware | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |


#### Context Output for **`summary_type=destination`**  for base command **`umbrella-reporting-summary-list`**

| **Path** | **Type** | **Description**    |
| --- |----------|--------------------|
| UmbrellaReporting.SummaryWithDestination.domain | String   | Destination domain.|
| UmbrellaReporting.SummaryWithDestination.summary.applications | Number   | Total number of applications \(avc or total\). | 
| UmbrellaReporting.SummaryWithDestination.summary.applicationsallowed | Number   | Total number of allowed applications. | 
| UmbrellaReporting.SummaryWithDestination.summary.applicationsblocked | Number   | Total number of blocked applications. | 
| UmbrellaReporting.SummaryWithDestination.summary.categories | Number   | Total number of categories. | 
| UmbrellaReporting.SummaryWithDestination.summary.domains | Number   | Total number of domains. | 
| UmbrellaReporting.SummaryWithDestination.summary.files | Number   | Total number of files. | 
| UmbrellaReporting.SummaryWithDestination.summary.filetypes | Number   | Total number of file types. | 
| UmbrellaReporting.SummaryWithDestination.summary.identities | Number   | Total number of identities. | 
| UmbrellaReporting.SummaryWithDestination.summary.identitytypes | Number   | Total number of identity types. | 
| UmbrellaReporting.SummaryWithDestination.summary.policycategories | Number   | Total number of blocked categories. | 
| UmbrellaReporting.SummaryWithDestination.summary.policyrequests | Number   | Total number of policy requests. | 
| UmbrellaReporting.SummaryWithDestination.summary.requests | Number   | Total number of requests. | 
| UmbrellaReporting.SummaryWithDestination.summary.requestsallowed | Number   | Total number of allowed requests. | 
| UmbrellaReporting.SummaryWithDestination.summary.requestsblocked | Number   | Total number of blocked requests. |


#### Command example for **`summary_type=destination`**  for base command **`umbrella-reporting-summary-list`**
```!umbrella-reporting-summary-list summary_type=destination limit=1```

#### Context Example for **`summary_type=destination`**  for base command **`umbrella-reporting-summary-list`**
```json
{
   "UmbrellaReporting":{
      "SummaryWithDestination":[
        {
            "domain": "dummy.domain.com",
            "summary": {
                "applications": 0,
                "domains": 0,
                "requestsblocked": 0,
                "filetypes": 0,
                "policycategories": 0,
                "policyrequests": 0,
                "requests": 0,
                "requestsallowed": 0,
                "categories": 0,
                "identitytypes": 0,
                "applicationsblocked": 0,
                "files": 0,
                "identities": 0,
                "applicationsallowed": 0
            }
        }
    ]
   }
}
```
#### Human Readable Output

>### Summary with Destination List 
>|Destination| Application|Allowed Application|Blocked Application|Category|Domain|File|File Type|Identity|Identity Type|Policy Category|Policy Request|Request|Allowed Request|Blocked Request|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| www.google.com | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |


#### Context Output for **`summary_type=intrusion_rule`**  for base command **`umbrella-reporting-summary-list`**

| **Path** | **Type** | **Description**                                |
| --- |----------|------------------------------------------------|
| UmbrellaReporting.SignatureListSummary.signaturelist.id | Number   | Unique id assigned to a Default or Custom Signature List.   |
| UmbrellaReporting.SignatureListSummary.signatures.generatorid | Number   | Generator id. | 
| UmbrellaReporting.SignatureListSummary.signatures.id | Number   |Signature ID. | 
| UmbrellaReporting.SignatureListSummary.signatures.lasteventat | Number   | Last Eevent At. | 
| UmbrellaReporting.SignatureListSummary.signatures.counts.blocked | Number   | Blocked | 
| UmbrellaReporting.SignatureListSummary.signatures.counts.detected | Number   | Detected. |
| UmbrellaReporting.SignatureListSummary.signatures.counts.wouldblock | Number   | Would Block. |


#### Command example for **`summary_type=intrusion_rule`**  for base command **`umbrella-reporting-summary-list`**
```!umbrella-reporting-summary-list summary_type=intrusion_rule limit=1```


#### Context Example for **`summary_type=intrusion_rule`**  for base command **`umbrella-reporting-summary-list`**
```json
{
   "UmbrellaReporting":{
      "SignatureListSummary":[
        {
            "signaturelist": { "id": 1111 },
            "signatures": [
                {
                    "counts": {
                        "blocked": 0,
                        "detected": 1,
                        "wouldblock": 0
                    },
                    "generatorid": 1,
                    "lasteventat": 1594557262000,
                    "id": 47829
                }
            ]
        }
    ]
   }
}
```

#### Human Readable Output

>### Summary with Intrusion List 
>|Blocked| Detected | Would Block | Last Event |
>|---|---|---|---|
>| 0 | 1 | 0 | 1594557262000 |