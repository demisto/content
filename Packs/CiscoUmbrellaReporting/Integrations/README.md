The Umbrella Reporting v2 API provides visibility into your core network and security activities and Umbrella logs.
This integration was integrated and tested with version xx of Cisco Umbrella Reporting

## Configure Cisco Umbrella Reporting on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco Umbrella Reporting.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API URL | Cisco Umbrella Reporting API base URL. | True |
    | Organization ID | Organization ID | True |
    | Client ID | Client ID and Client Secret. | True |
    | Client Secret |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| limit | The maximum number of records to return from the collection. Default is 50. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. | Optional | 


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
                        "label": "Software/Technology",
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
                "count": 119,
                "counts": {
                    "allowedrequests": 119,
                    "blockedrequests": 0,
                    "requests": 119
                },
                "domain": "presence.teams.microsoft.com",
                "policycategories": [],
                "rank": 1
            },
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
                        "label": "Software/Technology",
                        "type": "content"
                    }
                ],
                "count": 110,
                "counts": {
                    "allowedrequests": 110,
                    "blockedrequests": 0,
                    "requests": 110
                },
                "domain": "api.apple-cloudkit.com",
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
>| presence.teams.microsoft.com | Business and Industry, Computers and Internet, Online Meetings, Application, Software/Technology, Business Services | 119 | 0 | 119 |
>| api.apple-cloudkit.com | Computers and Internet, Infrastructure and Content Delivery Networks, Application, Software/Technology | 110 | 0 | 110 |


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
| limit | The maximum number of records to return from the collection. Default is 50. | Optional | 
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
| page_size | The number of requested results per page. | Optional | 


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
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 25,
                    "integration": false,
                    "label": "Software/Technology",
                    "type": "content"
                },
                "count": 3312,
                "rank": 1
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 148,
                    "integration": false,
                    "label": "Application",
                    "type": "application"
                },
                "count": 3204,
                "rank": 2
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 167,
                    "integration": false,
                    "label": "Computers and Internet",
                    "type": "content"
                },
                "count": 2755,
                "rank": 3
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 123,
                    "integration": false,
                    "label": "Infrastructure and Content Delivery Networks",
                    "type": "content"
                },
                "count": 2311,
                "rank": 4
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 32,
                    "integration": false,
                    "label": "Business Services",
                    "type": "content"
                },
                "count": 1759,
                "rank": 5
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 163,
                    "integration": false,
                    "label": "Business and Industry",
                    "type": "content"
                },
                "count": 1170,
                "rank": 6
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 142,
                    "integration": false,
                    "label": "Online Meetings",
                    "type": "content"
                },
                "count": 477,
                "rank": 7
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 23,
                    "integration": false,
                    "label": "Search Engines",
                    "type": "content"
                },
                "count": 376,
                "rank": 8
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 4,
                    "integration": false,
                    "label": "Chat",
                    "type": "content"
                },
                "count": 353,
                "rank": 9
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 15,
                    "integration": false,
                    "label": "Instant Messaging",
                    "type": "content"
                },
                "count": 348,
                "rank": 10
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 164,
                    "integration": false,
                    "label": "Chat and Instant Messaging",
                    "type": "content"
                },
                "count": 249,
                "rank": 11
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 190,
                    "integration": false,
                    "label": "Search Engines and Portals",
                    "type": "content"
                },
                "count": 247,
                "rank": 12
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 31,
                    "integration": false,
                    "label": "Webmail",
                    "type": "content"
                },
                "count": 223,
                "rank": 13
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 27,
                    "integration": false,
                    "label": "Advertisements",
                    "type": "content"
                },
                "count": 196,
                "rank": 14
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 205,
                    "integration": false,
                    "label": "Online Document Sharing and Collaboration",
                    "type": "content"
                },
                "count": 164,
                "rank": 15
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 162,
                    "integration": false,
                    "label": "Web-based Email",
                    "type": "content"
                },
                "count": 163,
                "rank": 16
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 141,
                    "integration": false,
                    "label": "Organizational Email",
                    "type": "content"
                },
                "count": 163,
                "rank": 17
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 198,
                    "integration": false,
                    "label": "Cloud and Data Centers",
                    "type": "content"
                },
                "count": 134,
                "rank": 18
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 132,
                    "integration": false,
                    "label": "SaaS and B2B",
                    "type": "content"
                },
                "count": 112,
                "rank": 19
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 124,
                    "integration": false,
                    "label": "Internet Telephony",
                    "type": "content"
                },
                "count": 99,
                "rank": 20
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 9,
                    "integration": false,
                    "label": "File Storage",
                    "type": "content"
                },
                "count": 72,
                "rank": 21
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 184,
                    "integration": false,
                    "label": "Online Storage and Backup",
                    "type": "content"
                },
                "count": 72,
                "rank": 22
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 17,
                    "integration": false,
                    "label": "Movies",
                    "type": "content"
                },
                "count": 50,
                "rank": 23
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 36,
                    "integration": false,
                    "label": "Music",
                    "type": "content"
                },
                "count": 46,
                "rank": 24
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 138,
                    "integration": false,
                    "label": "Software Updates",
                    "type": "content"
                },
                "count": 40,
                "rank": 25
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 51,
                    "integration": false,
                    "label": "Podcasts",
                    "type": "content"
                },
                "count": 34,
                "rank": 26
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 8,
                    "integration": false,
                    "label": "Ecommerce/Shopping",
                    "type": "content"
                },
                "count": 25,
                "rank": 27
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 3,
                    "integration": false,
                    "label": "Blogs",
                    "type": "content"
                },
                "count": 25,
                "rank": 28
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 28,
                    "integration": false,
                    "label": "Video Sharing",
                    "type": "content"
                },
                "count": 16,
                "rank": 29
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 113,
                    "integration": false,
                    "label": "Computer Security",
                    "type": "content"
                },
                "count": 16,
                "rank": 30
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 119,
                    "integration": false,
                    "label": "Freeware and Shareware",
                    "type": "content"
                },
                "count": 16,
                "rank": 31
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 49,
                    "integration": false,
                    "label": "Forums/Message boards",
                    "type": "content"
                },
                "count": 15,
                "rank": 32
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 194,
                    "integration": false,
                    "label": "Streaming Video",
                    "type": "content"
                },
                "count": 14,
                "rank": 33
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 130,
                    "integration": false,
                    "label": "Professional Networking",
                    "type": "content"
                },
                "count": 13,
                "rank": 34
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 54,
                    "integration": false,
                    "label": "Research/Reference",
                    "type": "content"
                },
                "count": 12,
                "rank": 35
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 24,
                    "integration": false,
                    "label": "Social Networking",
                    "type": "content"
                },
                "count": 11,
                "rank": 36
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 191,
                    "integration": false,
                    "label": "Shopping",
                    "type": "content"
                },
                "count": 9,
                "rank": 37
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 16,
                    "integration": false,
                    "label": "Jobs/Employment",
                    "type": "content"
                },
                "count": 7,
                "rank": 38
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 183,
                    "integration": false,
                    "label": "Online Communities",
                    "type": "content"
                },
                "count": 6,
                "rank": 39
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 29,
                    "integration": false,
                    "label": "Visual Search Engines",
                    "type": "content"
                },
                "count": 4,
                "rank": 40
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 187,
                    "integration": false,
                    "label": "Photo Search and Images",
                    "type": "content"
                },
                "count": 4,
                "rank": 41
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 20,
                    "integration": false,
                    "label": "Photo Sharing",
                    "type": "content"
                },
                "count": 4,
                "rank": 42
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 21,
                    "integration": false,
                    "label": "Portals",
                    "type": "content"
                },
                "count": 3,
                "rank": 43
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 18,
                    "integration": false,
                    "label": "News/Media",
                    "type": "content"
                },
                "count": 2,
                "rank": 44
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 34,
                    "integration": false,
                    "label": "Financial Institutions",
                    "type": "content"
                },
                "count": 2,
                "rank": 45
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 134,
                    "integration": false,
                    "label": "Science and Technology",
                    "type": "content"
                },
                "count": 2,
                "rank": 46
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 168,
                    "integration": false,
                    "label": "Education",
                    "type": "content"
                },
                "count": 2,
                "rank": 47
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 22,
                    "integration": false,
                    "label": "Radio",
                    "type": "content"
                },
                "count": 2,
                "rank": 48
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 33,
                    "integration": false,
                    "label": "Educational Institutions",
                    "type": "content"
                },
                "count": 2,
                "rank": 49
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 172,
                    "integration": false,
                    "label": "Finance",
                    "type": "content"
                },
                "count": 2,
                "rank": 50
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 71,
                    "integration": false,
                    "label": "Block List",
                    "type": "customer"
                },
                "count": 1,
                "rank": 51
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 140,
                    "integration": false,
                    "label": "Web Page Translation",
                    "type": "content"
                },
                "count": 1,
                "rank": 52
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 180,
                    "integration": false,
                    "label": "Non-governmental Organizations",
                    "type": "content"
                },
                "count": 1,
                "rank": 53
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 129,
                    "integration": false,
                    "label": "Personal Sites",
                    "type": "content"
                },
                "count": 1,
                "rank": 54
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 50,
                    "integration": false,
                    "label": "Non-Profits",
                    "type": "content"
                },
                "count": 1,
                "rank": 55
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 188,
                    "integration": false,
                    "label": "Reference",
                    "type": "content"
                },
                "count": 1,
                "rank": 56
            }
        ]
    }
}
```

#### Human Readable Output

>### Category List
>|Category|Type|Activity|
>|---|---|---|
>| Software/Technology | content | 3312 |
>| Application | application | 3204 |
>| Computers and Internet | content | 2755 |
>| Infrastructure and Content Delivery Networks | content | 2311 |
>| Business Services | content | 1759 |
>| Business and Industry | content | 1170 |
>| Online Meetings | content | 477 |
>| Search Engines | content | 376 |
>| Chat | content | 353 |
>| Instant Messaging | content | 348 |
>| Chat and Instant Messaging | content | 249 |
>| Search Engines and Portals | content | 247 |
>| Webmail | content | 223 |
>| Advertisements | content | 196 |
>| Online Document Sharing and Collaboration | content | 164 |
>| Web-based Email | content | 163 |
>| Organizational Email | content | 163 |
>| Cloud and Data Centers | content | 134 |
>| SaaS and B2B | content | 112 |
>| Internet Telephony | content | 99 |
>| File Storage | content | 72 |
>| Online Storage and Backup | content | 72 |
>| Movies | content | 50 |
>| Music | content | 46 |
>| Software Updates | content | 40 |
>| Podcasts | content | 34 |
>| Ecommerce/Shopping | content | 25 |
>| Blogs | content | 25 |
>| Video Sharing | content | 16 |
>| Computer Security | content | 16 |
>| Freeware and Shareware | content | 16 |
>| Forums/Message boards | content | 15 |
>| Streaming Video | content | 14 |
>| Professional Networking | content | 13 |
>| Research/Reference | content | 12 |
>| Social Networking | content | 11 |
>| Shopping | content | 9 |
>| Jobs/Employment | content | 7 |
>| Online Communities | content | 6 |
>| Visual Search Engines | content | 4 |
>| Photo Search and Images | content | 4 |
>| Photo Sharing | content | 4 |
>| Portals | content | 3 |
>| News/Media | content | 2 |
>| Financial Institutions | content | 2 |
>| Science and Technology | content | 2 |
>| Education | content | 2 |
>| Radio | content | 2 |
>| Educational Institutions | content | 2 |
>| Finance | content | 2 |
>| Block List | customer | 1 |
>| Web Page Translation | content | 1 |
>| Non-governmental Organizations | content | 1 |
>| Personal Sites | content | 1 |
>| Non-Profits | content | 1 |
>| Reference | content | 1 |


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
| limit | The maximum number of records to return from the collection. Default is 50. | Optional | 
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
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. | Optional | 


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
                "bandwidth": null,
                "counts": {
                    "allowedrequests": 4947,
                    "blockedrequests": 1,
                    "requests": 4962
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
                "rank": 1,
                "requests": 4962
            }
        ]
    }
}
```

#### Human Readable Output

>### Identities List
>|Identity|Requests|
>|---|---|
>| S’s MacBook Pro | 4962 |


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
| page_size | The number of requested results per page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.Eventtype.eventtype | String | The event type. One of "domain_security", "domain_integration", "url_security", "url_integration", "cisco_amp" and "antivirus". | 
| UmbrellaReporting.Eventtype.count | Number | Number of requests made that match this event type. | 
| UmbrellaReporting.EventType.count | Number |  | 
| UmbrellaReporting.EventType.eventtype | String |  | 

#### Command example
```!umbrella-reporting-event-type-list```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "EventType": [
            {
                "count": 0,
                "eventtype": "application"
            },
            {
                "count": 0,
                "eventtype": "antivirus"
            },
            {
                "count": 0,
                "eventtype": "cisco_amp"
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
                "eventtype": "domain_integration"
            },
            {
                "count": 0,
                "eventtype": "domain_security"
            }
        ]
    }
}
```

#### Human Readable Output

>### Event Type List
>|Event Type|Count|
>|---|---|
>| application | 0 |
>| antivirus | 0 |
>| cisco_amp | 0 |
>| url_integration | 0 |
>| url_security | 0 |
>| domain_integration | 0 |
>| domain_security | 0 |


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
| limit | The maximum number of records to return from the collection. Default is 50. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| urls | A URL or comma-separated list of URLs. | Optional | 
| ip | An IP address. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| sha256 | A SHA-256 hash. | Optional | 
| amp_disposition | An Advanced Malware Protection (AMP) disposition string. Possible values are: clean, malicious, unknown. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. | Optional | 


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
#### Human Readable Output

>UmbrellaReporting does not have file to present. 


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
| limit | The maximum number of records to return from the collection. Default is 50. | Optional | 
| domains | A domain name or comma-separated list of domain names. | Optional | 
| ip | An IP address. | Optional | 
| identity_types | An identity type or comma-separated list of identity types. | Optional | 
| verdict | A verdict string. Possible values are: allowed, blocked, proxied. | Optional | 
| threats | A threat name or comma-separated list of threat names. | Optional | 
| threat_types | A threat type or comma-separated list of threat types. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.Threat.threat | String | The threat name. | 
| UmbrellaReporting.Threat.threattype | String | The threat type. | 
| UmbrellaReporting.Threat.count | Number | The number of requests for that threat name. | 

#### Command example
```!umbrella-reporting-threat-list limit=1```
#### Human Readable Output

>UmbrellaReporting does not have threat to present. 


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
| limit | The maximum number of records to return from the collection. Default is 50. | Optional | 
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
| page_size | The number of requested results per page. | Optional | 


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
| UmbrellaReporting.Activity.device.id | Unknown |  | 

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
                            "id": 7,
                            "label": "Collaboration"
                        },
                        "id": 315463,
                        "label": "Slack"
                    }
                ],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": true,
                        "id": 4,
                        "integration": false,
                        "label": "Chat",
                        "type": "content"
                    },
                    {
                        "deprecated": true,
                        "id": 15,
                        "integration": false,
                        "label": "Instant Messaging",
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
                        "deprecated": false,
                        "id": 164,
                        "integration": false,
                        "label": "Chat and Instant Messaging",
                        "type": "content"
                    }
                ],
                "date": "2022-11-09",
                "device": {
                    "id": null
                },
                "domain": "slack.com",
                "externalip": "182.76.175.118",
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
                "internalip": "192.168.0.105",
                "policycategories": [],
                "querytype": "A",
                "returncode": 0,
                "threats": [],
                "time": "06:38:37",
                "timestamp": 1667975917000,
                "type": "dns",
                "verdict": "allowed"
            },
            {
                "allapplications": [
                    {
                        "category": {
                            "id": 1,
                            "label": "Application Development and Testing"
                        },
                        "id": 288256,
                        "label": "GitHub"
                    }
                ],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": true,
                        "id": 25,
                        "integration": false,
                        "label": "Software/Technology",
                        "type": "content"
                    },
                    {
                        "deprecated": true,
                        "id": 32,
                        "integration": false,
                        "label": "Business Services",
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
                        "deprecated": false,
                        "id": 167,
                        "integration": false,
                        "label": "Computers and Internet",
                        "type": "content"
                    }
                ],
                "date": "2022-11-09",
                "device": {
                    "id": null
                },
                "domain": "alive.github.com",
                "externalip": "182.76.175.118",
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
                "internalip": "192.168.0.105",
                "policycategories": [],
                "querytype": "A",
                "returncode": 0,
                "threats": [],
                "time": "06:38:28",
                "timestamp": 1667975908000,
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
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| dns | S’s MacBook Pro | S’s MacBook Pro | slack.com | 192.168.0.105 | 182.76.175.118 | A | allowed | Chat, Instant Messaging, Application, Chat and Instant Messaging | Slack | Collaboration | 2022-11-09T06:38:37Z |
>| dns | S’s MacBook Pro | S’s MacBook Pro | alive.github.com | 192.168.0.105 | 182.76.175.118 | A | allowed | Software/Technology, Business Services, Application, Computers and Internet | GitHub | Application Development and Testing | 2022-11-09T06:38:28Z |


### umbrella-reporting-activity-get
***
List all entries within a time frame based on the traffic type selected. Valid activity types are dns, proxy, firewall, intrusion, ip, amp.
Only one activity type can be selected at a time.


#### Base Command

`umbrella-reporting-activity-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| traffic_type | Specify the type of traffic.  By default, all supported traffic types are included.<br/><br/> Supported optional parameters for DNS traffic type are limit, from,  to, offset, domains, ip, verdict, threats, threat_types.<br/>  Supported optional parameters for Proxy traffic type are limit, from, to, offset, domains, ip, verdict, threats, threat_types, urls, ports, identity_types, file_name, amp_disposition.<br/>  Supported optional parameters for Firewall traffic type are limit, from, to, offset, ip, ports, verdict.<br/>  Supported optional parameters for Intrusion traffic type are limit, from, to, offset, ip, ports, signatures, intrusion_action.<br/>  Supported optional parameters for IP traffic type are limit, from, to, offset, ip, ports, identity_types, verdict.<br/>  Supported optional parameters for Advanced Malware Protection (AMP) traffic type are limit, from, to, offset, amp_disposition, sha256. Possible values are: dns, proxy, firewall, intrusion, ip, amp. | Required | 
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| limit | The maximum number of records to return from the collection. Default is 50. | Optional | 
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
| page_size | The number of requested results per page. | Optional | 
| signatures | List of -, comma separated. | Optional | 
| intrusion_action | Comma-separated list of intrusion actions. Possible values: would_block, blocked, detected. | Optional | 


#### Context Output

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
| UmbrellaReporting.ActivityDns.device.id | Unknown |  | 
| UmbrellaReporting.ActivityProxy.amp.disposition | String |  | 
| UmbrellaReporting.ActivityProxy.amp.malware | String |  | 
| UmbrellaReporting.ActivityProxy.amp.score | Number |  | 
| UmbrellaReporting.ActivityProxy.blockedfiletype | String |  | 
| UmbrellaReporting.ActivityProxy.bundleid | Number |  | 
| UmbrellaReporting.ActivityProxy.categories.deprecated | Boolean |  | 
| UmbrellaReporting.ActivityProxy.categories.id | Number |  | 
| UmbrellaReporting.ActivityProxy.categories.integration | Boolean |  | 
| UmbrellaReporting.ActivityProxy.categories.label | String |  | 
| UmbrellaReporting.ActivityProxy.categories.type | String |  | 
| UmbrellaReporting.ActivityProxy.contenttype | String |  | 
| UmbrellaReporting.ActivityProxy.datacenter.id | String |  | 
| UmbrellaReporting.ActivityProxy.datacenter.label | String |  | 
| UmbrellaReporting.ActivityProxy.datalossprevention.state | String |  | 
| UmbrellaReporting.ActivityProxy.date | Date |  | 
| UmbrellaReporting.ActivityProxy.destinationip | String |  | 
| UmbrellaReporting.ActivityProxy.egress.ip | String |  | 
| UmbrellaReporting.ActivityProxy.egress.type | String |  | 
| UmbrellaReporting.ActivityProxy.externalip | String |  | 
| UmbrellaReporting.ActivityProxy.forwardingmethod | String |  | 
| UmbrellaReporting.ActivityProxy.identities.deleted | Boolean |  | 
| UmbrellaReporting.ActivityProxy.identities.id | Number |  | 
| UmbrellaReporting.ActivityProxy.identities.label | String |  | 
| UmbrellaReporting.ActivityProxy.identities.type.id | Number |  | 
| UmbrellaReporting.ActivityProxy.identities.type.label | String |  | 
| UmbrellaReporting.ActivityProxy.identities.type.type | String |  | 
| UmbrellaReporting.ActivityProxy.internalip | String |  | 
| UmbrellaReporting.ActivityProxy.isolated.fileaction | String |  | 
| UmbrellaReporting.ActivityProxy.isolated.state | String |  | 
| UmbrellaReporting.ActivityProxy.policy.ruleid | Unknown |  | 
| UmbrellaReporting.ActivityProxy.policy.rulesetid | Unknown |  | 
| UmbrellaReporting.ActivityProxy.policy.timebasedrule | Boolean |  | 
| UmbrellaReporting.ActivityProxy.port | Number |  | 
| UmbrellaReporting.ActivityProxy.referer | String |  | 
| UmbrellaReporting.ActivityProxy.requestmethod | String |  | 
| UmbrellaReporting.ActivityProxy.requestsize | Number |  | 
| UmbrellaReporting.ActivityProxy.responsefilename | String |  | 
| UmbrellaReporting.ActivityProxy.responsesize | Number |  | 
| UmbrellaReporting.ActivityProxy.securityoverridden | Boolean |  | 
| UmbrellaReporting.ActivityProxy.sha256 | String |  | 
| UmbrellaReporting.ActivityProxy.statuscode | Number |  | 
| UmbrellaReporting.ActivityProxy.tenantcontrols | Boolean |  | 
| UmbrellaReporting.ActivityProxy.time | String |  | 
| UmbrellaReporting.ActivityProxy.timestamp | Date |  | 
| UmbrellaReporting.ActivityProxy.type | String |  | 
| UmbrellaReporting.ActivityProxy.url | String |  | 
| UmbrellaReporting.ActivityProxy.useragent | String |  | 
| UmbrellaReporting.ActivityProxy.verdict | String |  | 
| UmbrellaReporting.ActivityProxy.warnstatus | String |  | 

#### Command example
```!umbrella-reporting-activity-get traffic_type=dns limit=2```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "ActivityDns": [
            {
                "allapplications": [
                    {
                        "category": {
                            "id": 7,
                            "label": "Collaboration"
                        },
                        "id": 315463,
                        "label": "Slack"
                    }
                ],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": true,
                        "id": 4,
                        "integration": false,
                        "label": "Chat",
                        "type": "content"
                    },
                    {
                        "deprecated": true,
                        "id": 15,
                        "integration": false,
                        "label": "Instant Messaging",
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
                        "deprecated": false,
                        "id": 164,
                        "integration": false,
                        "label": "Chat and Instant Messaging",
                        "type": "content"
                    }
                ],
                "date": "2022-11-09",
                "device": {
                    "id": null
                },
                "domain": "slack.com",
                "externalip": "182.76.175.118",
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
                "internalip": "192.168.0.105",
                "policycategories": [],
                "querytype": "A",
                "returncode": 0,
                "threats": [],
                "time": "06:38:37",
                "timestamp": 1667975917000,
                "type": "dns",
                "verdict": "allowed"
            },
            {
                "allapplications": [
                    {
                        "category": {
                            "id": 1,
                            "label": "Application Development and Testing"
                        },
                        "id": 288256,
                        "label": "GitHub"
                    }
                ],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": true,
                        "id": 25,
                        "integration": false,
                        "label": "Software/Technology",
                        "type": "content"
                    },
                    {
                        "deprecated": true,
                        "id": 32,
                        "integration": false,
                        "label": "Business Services",
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
                        "deprecated": false,
                        "id": 167,
                        "integration": false,
                        "label": "Computers and Internet",
                        "type": "content"
                    }
                ],
                "date": "2022-11-09",
                "device": {
                    "id": null
                },
                "domain": "alive.github.com",
                "externalip": "182.76.175.118",
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
                "internalip": "192.168.0.105",
                "policycategories": [],
                "querytype": "A",
                "returncode": 0,
                "threats": [],
                "time": "06:38:28",
                "timestamp": 1667975908000,
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
>| S’s MacBook Pro | S’s MacBook Pro | slack.com | 192.168.0.105 | 182.76.175.118 | A | allowed | Chat, Instant Messaging, Application, Chat and Instant Messaging | Slack | Collaboration | 2022-11-09T06:38:37Z |
>| S’s MacBook Pro | S’s MacBook Pro | alive.github.com | 192.168.0.105 | 182.76.175.118 | A | allowed | Software/Technology, Business Services, Application, Computers and Internet | GitHub | Application Development and Testing | 2022-11-09T06:38:28Z |


#### Command example
```!umbrella-reporting-activity-get traffic_type=amp limit=2```
#### Human Readable Output

>UmbrellaReporting does not have activity amp to present. 


#### Command example
```!umbrella-reporting-activity-get traffic_type=proxy limit=2 from=-30days to=now```
#### Context Example
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
                "destinationip": "104.89.120.43",
                "egress": {
                    "ip": "",
                    "type": ""
                },
                "externalip": "182.76.175.118",
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
                "internalip": "10.10.10.217",
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
                "sha256": "",
                "statuscode": 304,
                "tenantcontrols": false,
                "threats": [],
                "time": "09:38:32",
                "timestamp": 1665999512000,
                "type": "proxy",
                "url": "http://x1.c.lencr.org/",
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
                "destinationip": "104.89.120.43",
                "egress": {
                    "ip": "",
                    "type": ""
                },
                "externalip": "182.76.175.118",
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
                "internalip": "10.10.10.217",
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
                "sha256": "",
                "statuscode": 304,
                "tenantcontrols": false,
                "threats": [],
                "time": "08:36:16",
                "timestamp": 1665995776000,
                "type": "proxy",
                "url": "http://x1.c.lencr.org/",
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
>| DESKTOP-IIQVPJ7 | DESKTOP-IIQVPJ7 | 10.10.10.217 | 182.76.175.118 | allowed | Infrastructure and Content Delivery Networks | 2022-10-17T09:38:32Z |
>| DESKTOP-IIQVPJ7 | DESKTOP-IIQVPJ7 | 10.10.10.217 | 182.76.175.118 | allowed | Infrastructure and Content Delivery Networks | 2022-10-17T08:36:16Z |


#### Command example
```!umbrella-reporting-activity-get traffic_type=firewall limit=2```
#### Human Readable Output

>UmbrellaReporting does not have activity firewall to present. 


#### Command example
```!umbrella-reporting-activity-get traffic_type=intrusion limit=2```
#### Human Readable Output

>UmbrellaReporting does not have activity intrusion to present. 


#### Command example
```!umbrella-reporting-activity-get traffic_type=ip limit=2```
#### Human Readable Output

>UmbrellaReporting does not have activity ip to present. 


### umbrella-reporting-summary-list
***
Get the summary.


#### Base Command

`umbrella-reporting-summary-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| summary_type | Get summary list of different summary types. Valid values for summary_type are category, destination, intrusion_rule.<br/>If summary type is not provided by the user, then all summary types i.e., category, destination, intrusion_rule will be considered.<br/>Supported optional parameters for category summary type are domain, urls, ip, identity_types, verdict, file_name, threats, threat_types, amp_disposition.<br/>Supported optional parameters for destination summary type are domain, urls, ip, identity_types, verdict, file_name, threats, threat_types, amp_disposition.<br/>Supported optional parameters for intrusion_rule summary type are signatures, ip, identity_types, intrusion_action, ports. Possible values are: category, destination, intrusion_rule. | Optional | 
| from | A timestamp (milliseconds) or relative time string (for example:-1days' or '1639146300000'). Filter for data that appears after this time. Default is -7days. | Optional | 
| to | A timestamp (milliseconds) or relative time string (for example:'now' or 1661510185000). Filter for data that appears before this time. Default is 'now'. | Optional | 
| limit | The maximum number of records to return from the collection. Default is 50. | Optional | 
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
| page_size | The number of requested results per page. | Optional | 
| signatures | List of -, comma separated. | Optional | 
| intrusion_action | Comma-separated List of intrusion actions. Possible values: would_block, blocked, detected. | Optional | 


#### Context Output

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
| UmbrellaReporting.SummaryWithCategory.category.deprecated | Boolean |  | 
| UmbrellaReporting.SummaryWithCategory.category.id | Number |  | 
| UmbrellaReporting.SummaryWithCategory.category.integration | Boolean |  | 
| UmbrellaReporting.SummaryWithCategory.category.label | String |  | 
| UmbrellaReporting.SummaryWithCategory.category.type | String |  | 
| UmbrellaReporting.SummaryWithCategory.summary.applications | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.applicationsallowed | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.applicationsblocked | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.categories | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.domains | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.files | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.filetypes | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.identities | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.identitytypes | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.policycategories | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.policyrequests | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.requests | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.requestsallowed | Number |  | 
| UmbrellaReporting.SummaryWithCategory.summary.requestsblocked | Number |  | 
| UmbrellaReporting.SummaryWithDestination.domain | String |  | 
| UmbrellaReporting.SummaryWithDestination.summary.applications | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.applicationsallowed | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.applicationsblocked | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.categories | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.domains | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.files | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.filetypes | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.identities | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.identitytypes | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.policycategories | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.policyrequests | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.requests | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.requestsallowed | Number |  | 
| UmbrellaReporting.SummaryWithDestination.summary.requestsblocked | Number |  | 

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
            "categories": 0,
            "domains": 0,
            "files": 0,
            "filetypes": 0,
            "identities": 0,
            "identitytypes": 0,
            "policycategories": 0,
            "policyrequests": 0,
            "requests": 0,
            "requestsallowed": 0,
            "requestsblocked": 0
        }
    }
}
```

#### Human Readable Output

>### Summary List
>|Application|Allowed Application|Blocked Application|Category|Domain|File|File Type|Identity|Identity Type|Policy Category|Policy Request|Request|Allowed Request|Blocked Request|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |


#### Command example
```!umbrella-reporting-summary-list summary_type=destination limit=2```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "SummaryWithDestination": [
            {
                "domain": "presence.teams.microsoft.com",
                "summary": {
                    "applications": 0,
                    "applicationsallowed": 0,
                    "applicationsblocked": 0,
                    "categories": 6,
                    "domains": 1,
                    "files": 0,
                    "filetypes": 0,
                    "identities": 2,
                    "identitytypes": 2,
                    "policycategories": 0,
                    "policyrequests": 0,
                    "requests": 119,
                    "requestsallowed": 119,
                    "requestsblocked": 0
                }
            },
            {
                "domain": "www.apple.com",
                "summary": {
                    "applications": 0,
                    "applicationsallowed": 0,
                    "applicationsblocked": 0,
                    "categories": 4,
                    "domains": 1,
                    "files": 0,
                    "filetypes": 0,
                    "identities": 2,
                    "identitytypes": 2,
                    "policycategories": 0,
                    "policyrequests": 0,
                    "requests": 110,
                    "requestsallowed": 110,
                    "requestsblocked": 0
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Summary with Destination List
>|Destination|Application|Allowed Application|Blocked Application|Category|Domain|File|File Type|Identity|Identity Type|Policy Category|Policy Request|Request|Allowed Request|Blocked Request|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| presence.teams.microsoft.com | 0 | 0 | 0 | 6 | 1 | 0 | 0 | 2 | 2 | 0 | 0 | 119 | 119 | 0 |
>| www.apple.com | 0 | 0 | 0 | 4 | 1 | 0 | 0 | 2 | 2 | 0 | 0 | 110 | 110 | 0 |


#### Command example
```!umbrella-reporting-summary-list summary_type=intrusion_rule limit=2```
#### Human Readable Output

>UmbrellaReporting does not have intrusion_rule summary to present. 

