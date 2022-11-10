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
```!umbrella-reporting-destination-list limit=2 from=-30days to=now```
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
                "count": 1098,
                "counts": {
                    "allowedrequests": 1098,
                    "blockedrequests": 0,
                    "requests": 1098
                },
                "domain": "www.cisco.com",
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
                "count": 1035,
                "counts": {
                    "allowedrequests": 1035,
                    "blockedrequests": 0,
                    "requests": 1035
                },
                "domain": "presence.teams.microsoft.com",
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
>| www.cisco.com | Computers and Internet, Infrastructure and Content Delivery Networks, Application, Software/Technology, Business Services | 1098 | 0 | 1098 |
>| presence.teams.microsoft.com | Business and Industry, Computers and Internet, Online Meetings, Application, Software/Technology, Business Services | 1035 | 0 | 1035 |


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
```!umbrella-reporting-category-list limit=2 from=-30days to=now```
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
                "count": 30588,
                "rank": 1
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 25,
                    "integration": false,
                    "label": "Software/Technology",
                    "type": "content"
                },
                "count": 26718,
                "rank": 2
            },
            {
                "bandwidth": 0,
                "category": {
                    "deprecated": false,
                    "id": 123,
                    "integration": false,
                    "label": "Infrastructure and Content Delivery Networks",
                    "type": "content"
                },
                "count": 20181,
                "rank": 3
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
                "count": 19095,
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
                "count": 17574,
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
                "count": 10290,
                "rank": 6
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
                "count": 5167,
                "rank": 7
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
                "count": 4085,
                "rank": 8
            },
            {
                "bandwidth": 7974662,
                "category": {
                    "deprecated": false,
                    "id": 142,
                    "integration": false,
                    "label": "Online Meetings",
                    "type": "content"
                },
                "count": 3918,
                "rank": 9
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
                "count": 3131,
                "rank": 10
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
                "count": 2550,
                "rank": 11
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
                "count": 2487,
                "rank": 12
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
                "count": 2412,
                "rank": 13
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
                "count": 2051,
                "rank": 14
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
                "count": 2005,
                "rank": 15
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
                "count": 1874,
                "rank": 16
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
                "count": 1770,
                "rank": 17
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
                "count": 1768,
                "rank": 18
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
                "count": 1648,
                "rank": 19
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
                "count": 1379,
                "rank": 20
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
                "count": 907,
                "rank": 21
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
                "count": 870,
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
                "count": 841,
                "rank": 23
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
                "count": 786,
                "rank": 24
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
                "count": 785,
                "rank": 25
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
                "count": 772,
                "rank": 26
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
                "count": 544,
                "rank": 27
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
                "count": 497,
                "rank": 28
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
                "count": 485,
                "rank": 29
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
                "count": 448,
                "rank": 30
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
                "count": 370,
                "rank": 31
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
                "count": 327,
                "rank": 32
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
                "count": 265,
                "rank": 33
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
                "count": 246,
                "rank": 34
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
                "count": 199,
                "rank": 35
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 202,
                    "integration": false,
                    "label": "Internet of Things",
                    "type": "content"
                },
                "count": 181,
                "rank": 36
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
                "count": 175,
                "rank": 37
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
                "count": 150,
                "rank": 38
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
                "count": 109,
                "rank": 39
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
                "count": 104,
                "rank": 40
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
                "count": 96,
                "rank": 41
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
                "count": 84,
                "rank": 42
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
                "count": 81,
                "rank": 43
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 182,
                    "integration": false,
                    "label": "Not Actionable",
                    "type": "content"
                },
                "count": 79,
                "rank": 44
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 201,
                    "integration": false,
                    "label": "DoH and DoT",
                    "type": "content"
                },
                "count": 78,
                "rank": 45
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
                "count": 78,
                "rank": 46
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
                "count": 78,
                "rank": 47
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 179,
                    "integration": false,
                    "label": "News",
                    "type": "content"
                },
                "count": 76,
                "rank": 48
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
                "count": 73,
                "rank": 49
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 107,
                    "integration": false,
                    "label": "URL Shorteners",
                    "type": "content"
                },
                "count": 70,
                "rank": 50
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
                "count": 64,
                "rank": 51
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
                "count": 61,
                "rank": 52
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 43,
                    "integration": false,
                    "label": "Proxy/Anonymizer",
                    "type": "content"
                },
                "count": 59,
                "rank": 53
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
                "count": 53,
                "rank": 54
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
                "count": 51,
                "rank": 55
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 169,
                    "integration": false,
                    "label": "Entertainment",
                    "type": "content"
                },
                "count": 39,
                "rank": 56
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
                "count": 29,
                "rank": 57
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 193,
                    "integration": false,
                    "label": "Streaming Audio",
                    "type": "content"
                },
                "count": 26,
                "rank": 58
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 177,
                    "integration": false,
                    "label": "Job Search",
                    "type": "content"
                },
                "count": 21,
                "rank": 59
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
                "count": 14,
                "rank": 60
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
                "count": 13,
                "rank": 61
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
                "count": 13,
                "rank": 62
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
                "count": 5,
                "rank": 63
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 139,
                    "integration": false,
                    "label": "Web Hosting",
                    "type": "content"
                },
                "count": 5,
                "rank": 64
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 11,
                    "integration": false,
                    "label": "Games",
                    "type": "content"
                },
                "count": 4,
                "rank": 65
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 55,
                    "integration": false,
                    "label": "Travel",
                    "type": "content"
                },
                "count": 4,
                "rank": 66
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 10,
                    "integration": false,
                    "label": "Gambling",
                    "type": "content"
                },
                "count": 2,
                "rank": 67
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 207,
                    "integration": false,
                    "label": "Recipes and Food",
                    "type": "content"
                },
                "count": 2,
                "rank": 68
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 126,
                    "integration": false,
                    "label": "Mobile Phones",
                    "type": "content"
                },
                "count": 2,
                "rank": 69
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 195,
                    "integration": false,
                    "label": "Transportation",
                    "type": "content"
                },
                "count": 2,
                "rank": 70
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 48,
                    "integration": false,
                    "label": "Automotive",
                    "type": "content"
                },
                "count": 2,
                "rank": 71
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
                "rank": 72
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 26,
                    "integration": false,
                    "label": "Television",
                    "type": "content"
                },
                "count": 1,
                "rank": 73
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 115,
                    "integration": false,
                    "label": "Dining and Drinking",
                    "type": "content"
                },
                "count": 1,
                "rank": 74
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 131,
                    "integration": false,
                    "label": "Real Estate",
                    "type": "content"
                },
                "count": 1,
                "rank": 75
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
                "rank": 76
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 144,
                    "integration": false,
                    "label": "Personal VPN",
                    "type": "content"
                },
                "count": 1,
                "rank": 77
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 175,
                    "integration": false,
                    "label": "Health and Medicine",
                    "type": "content"
                },
                "count": 1,
                "rank": 78
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": true,
                    "id": 58,
                    "integration": false,
                    "label": "Web Spam",
                    "type": "content"
                },
                "count": 1,
                "rank": 79
            },
            {
                "bandwidth": null,
                "category": {
                    "deprecated": false,
                    "id": 128,
                    "integration": false,
                    "label": "Online Trading",
                    "type": "content"
                },
                "count": 1,
                "rank": 80
            }
        ]
    }
}
```

#### Human Readable Output

>### Category List
>|Category|Type|Activity|
>|---|---|---|
>| Application | application | 30588 |
>| Software/Technology | content | 26718 |
>| Infrastructure and Content Delivery Networks | content | 20181 |
>| Computers and Internet | content | 19095 |
>| Business Services | content | 17574 |
>| Business and Industry | content | 10290 |
>| Search Engines | content | 5167 |
>| Search Engines and Portals | content | 4085 |
>| Online Meetings | content | 3918 |
>| SaaS and B2B | content | 3131 |
>| Chat | content | 2550 |
>| Instant Messaging | content | 2487 |
>| Advertisements | content | 2412 |
>| Online Document Sharing and Collaboration | content | 2051 |
>| Webmail | content | 2005 |
>| Cloud and Data Centers | content | 1874 |
>| Web-based Email | content | 1770 |
>| Organizational Email | content | 1768 |
>| Chat and Instant Messaging | content | 1648 |
>| Ecommerce/Shopping | content | 1379 |
>| Shopping | content | 907 |
>| Video Sharing | content | 870 |
>| Movies | content | 841 |
>| Streaming Video | content | 786 |
>| Internet Telephony | content | 785 |
>| Software Updates | content | 772 |
>| Social Networking | content | 544 |
>| Computer Security | content | 497 |
>| File Storage | content | 485 |
>| Music | content | 448 |
>| Podcasts | content | 370 |
>| News/Media | content | 327 |
>| Online Storage and Backup | content | 265 |
>| Portals | content | 246 |
>| Blogs | content | 199 |
>| Internet of Things | content | 181 |
>| Research/Reference | content | 175 |
>| Professional Networking | content | 150 |
>| Jobs/Employment | content | 109 |
>| Forums/Message boards | content | 104 |
>| Block List | customer | 96 |
>| Reference | content | 84 |
>| Online Communities | content | 81 |
>| Not Actionable | content | 79 |
>| DoH and DoT | content | 78 |
>| Education | content | 78 |
>| Educational Institutions | content | 78 |
>| News | content | 76 |
>| Financial Institutions | content | 73 |
>| URL Shorteners | content | 70 |
>| Freeware and Shareware | content | 64 |
>| Science and Technology | content | 61 |
>| Proxy/Anonymizer | content | 59 |
>| Non-Profits | content | 53 |
>| Finance | content | 51 |
>| Entertainment | content | 39 |
>| Photo Sharing | content | 29 |
>| Streaming Audio | content | 26 |
>| Job Search | content | 21 |
>| Radio | content | 14 |
>| Visual Search Engines | content | 13 |
>| Photo Search and Images | content | 13 |
>| Non-governmental Organizations | content | 5 |
>| Web Hosting | content | 5 |
>| Games | content | 4 |
>| Travel | content | 4 |
>| Gambling | content | 2 |
>| Recipes and Food | content | 2 |
>| Mobile Phones | content | 2 |
>| Transportation | content | 2 |
>| Automotive | content | 2 |
>| Web Page Translation | content | 1 |
>| Television | content | 1 |
>| Dining and Drinking | content | 1 |
>| Real Estate | content | 1 |
>| Personal Sites | content | 1 |
>| Personal VPN | content | 1 |
>| Health and Medicine | content | 1 |
>| Web Spam | content | 1 |
>| Online Trading | content | 1 |


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
```!umbrella-reporting-identity-list limit=2 from=-30days to=now```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "Identity": [
            {
                "bandwidth": null,
                "counts": {
                    "allowedrequests": 22984,
                    "blockedrequests": 43,
                    "requests": 23118
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
                "requests": 23118
            },
            {
                "bandwidth": 7974662,
                "counts": {
                    "allowedrequests": 22755,
                    "blockedrequests": 53,
                    "requests": 22906
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
                "rank": 2,
                "requests": 22906
            }
        ]
    }
}
```

#### Human Readable Output

>### Identities List
>|Identity|Requests|
>|---|---|
>| S’s MacBook Pro | 23118 |
>| DESKTOP-IIQVPJ7 | 22906 |


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
| UmbrellaReporting.EventType.eventtype | String | The event type. One of "domain_security", "domain_integration", "url_security", "url_integration", "cisco_amp" and "antivirus". | 
| UmbrellaReporting.EventType.count | Number | Number of requests made that match this event type. | 

#### Command example
```!umbrella-reporting-event-type-list from=-30days to=now```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "EventType": [
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
>| url_integration | 0 |
>| url_security | 0 |
>| antivirus | 0 |
>| application | 0 |
>| cisco_amp | 0 |
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
```!umbrella-reporting-file-list limit=2 from=-30days to=now```
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
                "sha256": "94fe42af4a67ed5be45bd7913d8a8aebc4e35afddd5675d01bd37df8e9b399ae"
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
```!umbrella-reporting-threat-list limit=1 from=-30days to=now```
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

#### Command example
```!umbrella-reporting-activity-list limit=2 from=-30days to=now```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "Activity": [
            {
                "allapplications": [],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": true,
                        "id": 23,
                        "integration": false,
                        "label": "Search Engines",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 190,
                        "integration": false,
                        "label": "Search Engines and Portals",
                        "type": "content"
                    }
                ],
                "date": "2022-11-09",
                "device": {
                    "id": null
                },
                "domain": "clientservices.googleapis.com",
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
                "time": "17:19:07",
                "timestamp": 1668014347000,
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
                        "id": 23,
                        "integration": false,
                        "label": "Search Engines",
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
                        "id": 190,
                        "integration": false,
                        "label": "Search Engines and Portals",
                        "type": "content"
                    }
                ],
                "date": "2022-11-09",
                "device": {
                    "id": null
                },
                "domain": "safebrowsing.googleapis.com",
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
                "time": "17:19:02",
                "timestamp": 1668014342000,
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
>| dns | S’s MacBook Pro | S’s MacBook Pro | clientservices.googleapis.com | 192.168.0.105 | 182.76.175.118 | A | allowed | Search Engines, Search Engines and Portals |  |  | 2022-11-09T17:19:07Z |
>| dns | S’s MacBook Pro | S’s MacBook Pro | safebrowsing.googleapis.com | 192.168.0.105 | 182.76.175.118 | A | allowed | Search Engines, Application, Search Engines and Portals | Do Not Decrypt Application | Sample Application Group | 2022-11-09T17:19:02Z |


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
| UmbrellaReporting.ActivityProxy.amp.disposition | String | Advanced Malware Protection \(AMP\) disposition. | 
| UmbrellaReporting.ActivityProxy.amp.malware | String | Advanced Malware Protection \(AMP\) malware. | 
| UmbrellaReporting.ActivityProxy.amp.score | Number | Advanced Malware Protection \(AMP\) score. | 
| UmbrellaReporting.ActivityProxy.blockedfiletype | String | Locked file type for entry. | 
| UmbrellaReporting.ActivityProxy.bundleid | Number | Bundleid. | 
| UmbrellaReporting.ActivityProxy.categories.deprecated | Boolean | If the category is a legacy category. | 
| UmbrellaReporting.ActivityProxy.categories.id | Number | ID of category. | 
| UmbrellaReporting.ActivityProxy.categories.integration | Boolean | If the category is an integration. | 
| UmbrellaReporting.ActivityProxy.categories.label | String | The human readable label of the category. | 
| UmbrellaReporting.ActivityProxy.categories.type | String | The type of category. | 
| UmbrellaReporting.ActivityProxy.contenttype | String | The type of web content, typically text/html. | 
| UmbrellaReporting.ActivityProxy.datacenter.id | String | Unique ID for the data center. | 
| UmbrellaReporting.ActivityProxy.datacenter.label | String | Name of the data center. | 
| UmbrellaReporting.ActivityProxy.datalossprevention.state | String | If the request was Blocked for DLP. Either 'blocked' or ''. | 
| UmbrellaReporting.ActivityProxy.date | Date | The date from the timestamp based on the timezone parameter. | 
| UmbrellaReporting.ActivityProxy.destinationip | String | Destination IP for entry. | 
| UmbrellaReporting.ActivityProxy.egress.ip | String | Egress IP. | 
| UmbrellaReporting.ActivityProxy.egress.type | String | Egress Type. | 
| UmbrellaReporting.ActivityProxy.externalip | String | External IP for entry. | 
| UmbrellaReporting.ActivityProxy.forwardingmethod | String | The request method \(GET, POST, HEAD, etc.\) | 
| UmbrellaReporting.ActivityProxy.identities.deleted | Boolean | Indicates whether the identity was deleted or not. | 
| UmbrellaReporting.ActivityProxy.identities.id | Number | ID of identity. | 
| UmbrellaReporting.ActivityProxy.identities.label | String | Label for identity. | 
| UmbrellaReporting.ActivityProxy.identities.type.id | Number | Origin type for identity. | 
| UmbrellaReporting.ActivityProxy.identities.type.label | String | Origin type label for identity. | 
| UmbrellaReporting.ActivityProxy.identities.type.type | String | Origin type name for identity. | 
| UmbrellaReporting.ActivityProxy.internalip | String | Internal IP for entry. | 
| UmbrellaReporting.ActivityProxy.isolated.fileaction | String | Isolated Fileaction. | 
| UmbrellaReporting.ActivityProxy.isolated.state | String | Isolated State. | 
| UmbrellaReporting.ActivityProxy.policy.ruleid | Number | The rule ID for the policy. | 
| UmbrellaReporting.ActivityProxy.policy.rulesetid | Number | The rule set ID for the policy. | 
| UmbrellaReporting.ActivityProxy.policy.timebasedrule | Boolean | Whether the policy triggered a time-of-day rule. | 
| UmbrellaReporting.ActivityProxy.policy.destinationlistids | Unknown | The destination lists that the policy triggered. | 
| UmbrellaReporting.ActivityProxy.port | Number | Request Port. | 
| UmbrellaReporting.ActivityProxy.referer | String | The referring domain or URL. | 
| UmbrellaReporting.ActivityProxy.requestmethod | String | The HTTP request method that was made. | 
| UmbrellaReporting.ActivityProxy.requestsize | Number | Request size in bytes. | 
| UmbrellaReporting.ActivityProxy.responsefilename | String | Response filename for entry. | 
| UmbrellaReporting.ActivityProxy.responsesize | Number | Response size in bytes. | 
| UmbrellaReporting.ActivityProxy.securityoverridden | Boolean | Security Overridden. | 
| UmbrellaReporting.ActivityProxy.sha256 | String | The hex digest of the response content. | 
| UmbrellaReporting.ActivityProxy.statuscode | Number | The HTTP status code; should always be 200 or 201. | 
| UmbrellaReporting.ActivityProxy.tenantcontrols | Boolean | If the request was part of a tenant control policy. | 
| UmbrellaReporting.ActivityProxy.time | String | The time in 24 hour format based on the timezone parameter. | 
| UmbrellaReporting.ActivityProxy.timestamp | Date | Timestamp in ms. | 
| UmbrellaReporting.ActivityProxy.type | String | Type of the request. A Proxy request always has type Proxy. | 
| UmbrellaReporting.ActivityProxy.url | String | The URL requested. | 
| UmbrellaReporting.ActivityProxy.useragent | String | The browser agent that made the request. | 
| UmbrellaReporting.ActivityProxy.verdict | String | Verdict for entry. | 
| UmbrellaReporting.ActivityProxy.warnstatus | String | Warn Status. | 
| UmbrellaReporting.ActivityProxy.policycategories.id | Number | ID of category. | 
| UmbrellaReporting.ActivityProxy.policycategories.label | String | The human readable label of the category. | 
| UmbrellaReporting.ActivityProxy.policycategories.type | String | Type of the request. A dns request always has type dns. | 
| UmbrellaReporting.ActivityProxy.policycategories.deprecated | Boolean | If the category is a legacy category. | 
| UmbrellaReporting.ActivityProxy.policycategories.integration | Boolean | If the category is an integration. | 
| UmbrellaReporting.ActivityProxy.antivirusthreats.others | Unknown | Other antivirus threats. | 
| UmbrellaReporting.ActivityProxy.antivirusthreats.puas | Unknown | Potentially unwanted applications. | 
| UmbrellaReporting.ActivityProxy.antivirusthreats.viruses | Unknown | Viruses. | 
| UmbrellaReporting.ActivityProxy.threats.label | String | The threat name or label. | 
| UmbrellaReporting.ActivityProxy.threats.type | String | The type of threat. | 
| UmbrellaReporting.ActivityProxy.allapplications.id | Number | ID of the application. | 
| UmbrellaReporting.ActivityProxy.allapplications.type | String | Type of the application, NBAR or AVC. | 
| UmbrellaReporting.ActivityProxy.allapplications.label | String | Label of the application. | 
| UmbrellaReporting.ActivityProxy.allapplications.category.label | String | Label of the application category. | 
| UmbrellaReporting.ActivityProxy.allapplications.category.id | Number | ID of the application category. | 
| UmbrellaReporting.ActivityProxy.allowedapplications.id | Number | ID of the application. | 
| UmbrellaReporting.ActivityProxy.allowedapplications.type | String | Type of the application, NBAR or AVC. | 
| UmbrellaReporting.ActivityProxy.allowedapplications.label | String | Label of the application. | 
| UmbrellaReporting.ActivityProxy.allowedapplications.category.label | String | Label of the application category. | 
| UmbrellaReporting.ActivityProxy.allowedapplications.category.id | Number | ID of the application category. | 
| UmbrellaReporting.ActivityProxy.blockedapplications.id | Number | ID of the application. | 
| UmbrellaReporting.ActivityProxy.blockedapplications.type | String | Type of the application, NBAR or AVC. | 
| UmbrellaReporting.ActivityProxy.blockedapplications.label | String | Label of the application. | 
| UmbrellaReporting.ActivityProxy.blockedapplications.category.label | String | Label of the application category. | 
| UmbrellaReporting.ActivityProxy.blockedapplications.category.id | Number | ID of the application category. | 
| UmbrellaReporting.ActivityProxy.httperrors.reason | String | The name of the error. | 
| UmbrellaReporting.ActivityProxy.httperrors.type | String | Type of the error CertificateError or TLSError.. | 
| UmbrellaReporting.ActivityProxy.httperrors.attributes | Unknown | Map of additional information about the error. | 
| UmbrellaReporting.ActivityProxy.httperrors.code | String | The http error code. | 
| UmbrellaReporting.ActivityAMPRetro.timestamp | Number | Timestamp in ms. | 
| UmbrellaReporting.ActivityAMPRetro.firstseenat | Number | First seen Timestamp. | 
| UmbrellaReporting.ActivityAMPRetro.disposition | String | Disposition for entry. | 
| UmbrellaReporting.ActivityAMPRetro.score | Number | Score for entry. | 
| UmbrellaReporting.ActivityAMPRetro.hostname | String | Hostname for entry. | 
| UmbrellaReporting.ActivityAMPRetro.malwarename | String | Malware name for entry. | 
| UmbrellaReporting.ActivityAMPRetro.sha256 | String | SHA256 for entry. | 
| UmbrellaReporting.ActivityFirewall.date | String | The date from the timestamp based on the timezone parameter. | 
| UmbrellaReporting.ActivityFirewall.destinationip | String | Destination IP for entry. | 
| UmbrellaReporting.ActivityFirewall.sourceip | String | Source IP for entry. | 
| UmbrellaReporting.ActivityFirewall.sourceport | Number | Source port for entry. | 
| UmbrellaReporting.ActivityFirewall.destinationport | Number | Destination port for entry. | 
| UmbrellaReporting.ActivityFirewall.verdict | String | Verdict for entry. | 
| UmbrellaReporting.ActivityFirewall.time | String | The time in 24 hour format based on the timezone parameter. | 
| UmbrellaReporting.ActivityFirewall.timestamp | Number | Timestamp in ms. | 
| UmbrellaReporting.ActivityFirewall.identities.id | Number | ID of identity. | 
| UmbrellaReporting.ActivityFirewall.identities.label | String | Label for identity. | 
| UmbrellaReporting.ActivityFirewall.identities.type.id | Number | Origin type for identity. | 
| UmbrellaReporting.ActivityFirewall.identities.type.label | String | Origin type label for identity. | 
| UmbrellaReporting.ActivityFirewall.identities.type.type | String | Origin type name for identity. | 
| UmbrellaReporting.ActivityFirewall.identities.deleted | Boolean | Indicates whether the identity was deleted or not. | 
| UmbrellaReporting.ActivityFirewall.protocol.id | Number | ID of protocol. | 
| UmbrellaReporting.ActivityFirewall.protocol.label | String | Name of the protocol. | 
| UmbrellaReporting.ActivityFirewall.rule.id | Number | ID of rule. | 
| UmbrellaReporting.ActivityFirewall.rule.label | String | Name of the rule. | 
| UmbrellaReporting.ActivityFirewall.rule.privateapplicationgroup.id | Number | ID of application group. | 
| UmbrellaReporting.ActivityFirewall.rule.privateapplicationgroup.label | String | Name of application group. | 
| UmbrellaReporting.ActivityFirewall.type | String | Type of the request. A Firewall request always has type Firewall. | 
| UmbrellaReporting.ActivityFirewall.allapplications.id | Number | ID of the application. | 
| UmbrellaReporting.ActivityFirewall.allapplications.label | String | Label of the application. | 
| UmbrellaReporting.ActivityFirewall.allapplications.app | String | Type: "IT Service Management" \(string\) - application/protocol type. | 
| UmbrellaReporting.ActivityFirewall.applicationprotocols.id | Number | ID of the application. | 
| UmbrellaReporting.ActivityFirewall.applicationprotocols.label | String | Application/Protocol label. | 
| UmbrellaReporting.ActivityFirewall.applicationprotocols.app | String | Type: "IT Service Management" \(string\) - application/protocol type. | 
| UmbrellaReporting.ActivityFirewall.packetsize | Number | The size of the packet that Umbrella CDFW received. | 
| UmbrellaReporting.ActivityFirewall.direction | String | The direction of the packet. It is destined either towards the internet or to the customer's network. | 
| UmbrellaReporting.ActivityIntrusion.type | String | Type of the request. A Intrusion request always has type Intrusion. | 
| UmbrellaReporting.ActivityIntrusion.date | String | The date from the timestamp based on the timezone parameter. | 
| UmbrellaReporting.ActivityIntrusion.destinationip | String | Destination IP for entry. | 
| UmbrellaReporting.ActivityIntrusion.protocol.id | Number | ID of protocol. | 
| UmbrellaReporting.ActivityIntrusion.protocol.label | String | Name of the protocol. | 
| UmbrellaReporting.ActivityIntrusion.sourceip | String | Source IP for entry. | 
| UmbrellaReporting.ActivityIntrusion.signaturelist.id | Number | Unique id assigned to a Default or Custom Signature List. | 
| UmbrellaReporting.ActivityIntrusion.classification | String | The category of attack detected by a rule that is part of a more general type of attack class, such as trojan-activity, attempted-user, and unknown. | 
| UmbrellaReporting.ActivityIntrusion.sourceport | Number | Source port for entry. | 
| UmbrellaReporting.ActivityIntrusion.sessionid | Number | The unique identifier of a session, which is used to group the correlated events between various services. | 
| UmbrellaReporting.ActivityIntrusion.verdict | String | Verdict for entry. | 
| UmbrellaReporting.ActivityIntrusion.destinationport | Number | Destination port for entry. | 
| UmbrellaReporting.ActivityIntrusion.timestamp | Date | Timestamp in ms. | 
| UmbrellaReporting.ActivityIntrusion.time | String | The time in 24 hour format based on the timezone parameter. | 
| UmbrellaReporting.ActivityIntrusion.identities.id | Number | ID of identity. | 
| UmbrellaReporting.ActivityIntrusion.identities.type.id | Number | Origin type for identity. | 
| UmbrellaReporting.ActivityIntrusion.identities.type.type | String | Origin type name for identity. | 
| UmbrellaReporting.ActivityIntrusion.identities.type.label | String | Origin type label for identity. | 
| UmbrellaReporting.ActivityIntrusion.identities.label | String | Label for identity. | 
| UmbrellaReporting.ActivityIntrusion.identities.deleted | Boolean | Indicates whether the identity was deleted or not. | 
| UmbrellaReporting.ActivityIntrusion.severity | String | The severity level of the rule, such as High, Medium, Low, and Very Low. | 
| UmbrellaReporting.ActivityIntrusion.signature.generatorid | Number | Unique id assigned to the part of the IPS which generated the event. | 
| UmbrellaReporting.ActivityIntrusion.signature.id | Number | ID of the application. | 
| UmbrellaReporting.ActivityIntrusion.signature.label | String | A brief description of the signature. | 
| UmbrellaReporting.ActivityIntrusion.signature.cves | String | An identifier for a known security vulnerability/exposure. | 
| UmbrellaReporting.ActivityIP.destinationip | String | Destination IP for entry. | 
| UmbrellaReporting.ActivityIP.sourceip | String | Source IP for entry. | 
| UmbrellaReporting.ActivityIP.date | String | The date from the timestamp based on the timezone parameter. | 
| UmbrellaReporting.ActivityIP.sourceport | Number | Source port for entry. | 
| UmbrellaReporting.ActivityIP.destinationport | Number | Destination port for entry. | 
| UmbrellaReporting.ActivityIP.verdict | String | Verdict for entry. | 
| UmbrellaReporting.ActivityIP.timestamp | Number | Timestamp in ms. | 
| UmbrellaReporting.ActivityIP.time | String | The time in 24 hour format based on the timezone parameter. | 
| UmbrellaReporting.ActivityIP.identities.id | Number | ID of identity. | 
| UmbrellaReporting.ActivityIP.identities.label | String | Label for identity | 
| UmbrellaReporting.ActivityIP.identities.type.id | Number | Origin type for identity. | 
| UmbrellaReporting.ActivityIP.identities.type.label | String | Origin type label for identity | 
| UmbrellaReporting.ActivityIP.identities.type.type | String | Origin type name for identity. | 
| UmbrellaReporting.ActivityIP.identities.deleted | Boolean | Indicates whether the identity was deleted or not. | 
| UmbrellaReporting.ActivityIP.categories.id | Number | ID of category. | 
| UmbrellaReporting.ActivityIP.categories.label | String | The human readable label of the category. | 
| UmbrellaReporting.ActivityIP.categories.type | String | The type of category. | 
| UmbrellaReporting.ActivityIP.categories.integration | Boolean | If the category is an integration | 
| UmbrellaReporting.ActivityIP.categories.deprecated | Boolean | If the category is a legacy category. | 
| UmbrellaReporting.ActivityIP.type | String | Type of the request. A IP request always has type IP. | 

#### Command example
```!umbrella-reporting-activity-get traffic_type=dns limit=2 from=-30days to=now```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "ActivityDns": [
            {
                "allapplications": [],
                "allowedapplications": [],
                "blockedapplications": [],
                "categories": [
                    {
                        "deprecated": true,
                        "id": 23,
                        "integration": false,
                        "label": "Search Engines",
                        "type": "content"
                    },
                    {
                        "deprecated": false,
                        "id": 190,
                        "integration": false,
                        "label": "Search Engines and Portals",
                        "type": "content"
                    }
                ],
                "date": "2022-11-09",
                "device": {
                    "id": null
                },
                "domain": "clientservices.googleapis.com",
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
                "time": "17:19:07",
                "timestamp": 1668014347000,
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
                        "id": 23,
                        "integration": false,
                        "label": "Search Engines",
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
                        "id": 190,
                        "integration": false,
                        "label": "Search Engines and Portals",
                        "type": "content"
                    }
                ],
                "date": "2022-11-09",
                "device": {
                    "id": null
                },
                "domain": "safebrowsing.googleapis.com",
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
                "time": "17:19:02",
                "timestamp": 1668014342000,
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
>| S’s MacBook Pro | S’s MacBook Pro | clientservices.googleapis.com | 192.168.0.105 | 182.76.175.118 | A | allowed | Search Engines, Search Engines and Portals |  |  | 2022-11-09T17:19:07Z |
>| S’s MacBook Pro | S’s MacBook Pro | safebrowsing.googleapis.com | 192.168.0.105 | 182.76.175.118 | A | allowed | Search Engines, Application, Search Engines and Portals | Do Not Decrypt Application | Sample Application Group | 2022-11-09T17:19:02Z |


#### Command example
```!umbrella-reporting-activity-get traffic_type=amp limit=2 from=-30days to=now```
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
```!umbrella-reporting-activity-get traffic_type=firewall limit=2 from=-30days to=now```
#### Human Readable Output

>UmbrellaReporting does not have activity firewall to present. 


#### Command example
```!umbrella-reporting-activity-get traffic_type=intrusion limit=2 from=-30days to=now```
#### Human Readable Output

>UmbrellaReporting does not have activity intrusion to present. 


#### Command example
```!umbrella-reporting-activity-get traffic_type=ip limit=2 from=-30days to=now```
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
| UmbrellaReporting.SummaryWithCategory.category.deprecated | Boolean | If the category is a legacy category. | 
| UmbrellaReporting.SummaryWithCategory.category.id | Number | ID of category. | 
| UmbrellaReporting.SummaryWithCategory.category.integration | Boolean | If the category is an integration. | 
| UmbrellaReporting.SummaryWithCategory.category.label | String | The human readable label of the category. | 
| UmbrellaReporting.SummaryWithCategory.category.type | String | The type of category. | 
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
| UmbrellaReporting.SummaryWithDestination.domain | String | Destination domain. | 
| UmbrellaReporting.SummaryWithDestination.summary.applications | Number | Total number of applications \(avc or total\). | 
| UmbrellaReporting.SummaryWithDestination.summary.applicationsallowed | Number | Total number of allowed applications. | 
| UmbrellaReporting.SummaryWithDestination.summary.applicationsblocked | Number | Total number of blocked applications. | 
| UmbrellaReporting.SummaryWithDestination.summary.categories | Number | Total number of categories. | 
| UmbrellaReporting.SummaryWithDestination.summary.domains | Number | Total number of domains. | 
| UmbrellaReporting.SummaryWithDestination.summary.files | Number | Total number of files. | 
| UmbrellaReporting.SummaryWithDestination.summary.filetypes | Number | Total number of file types. | 
| UmbrellaReporting.SummaryWithDestination.summary.identities | Number | Total number of identities. | 
| UmbrellaReporting.SummaryWithDestination.summary.identitytypes | Number | Total number of identity types. | 
| UmbrellaReporting.SummaryWithDestination.summary.policycategories | Number | Total number of blocked categories. | 
| UmbrellaReporting.SummaryWithDestination.summary.policyrequests | Number | Total number of policy requests. | 
| UmbrellaReporting.SummaryWithDestination.summary.requests | Number | Total number of requests. | 
| UmbrellaReporting.SummaryWithDestination.summary.requestsallowed | Number | Total number of allowed requests. | 
| UmbrellaReporting.SummaryWithDestination.summary.requestsblocked | Number | Total number of blocked requests. | 
| UmbrellaReporting.SignatureListSummary.signaturelist.id | Number | Unique id assigned to a Default or Custom Signature List. | 
| UmbrellaReporting.SignatureListSummary.signatures.counts.blocked | Number | Blocked. | 
| UmbrellaReporting.SignatureListSummary.signatures.counts.detected | Number | Detected. | 
| UmbrellaReporting.SignatureListSummary.signatures.counts.wouldblock | Number | Would Block. | 
| UmbrellaReporting.SignatureListSummary.signatures.generatorid | Number | Generator id. | 
| UmbrellaReporting.SignatureListSummary.signatures.lasteventat | Date | Last Eevent At. | 
| UmbrellaReporting.SignatureListSummary.signatures.id | Number | Signature ID. | 

#### Command example
```!umbrella-reporting-summary-list domains=api.tunnels.cdfw.umbrella.com from=-30days to=now```
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
            "identities": 1,
            "identitytypes": 1,
            "policycategories": 0,
            "policyrequests": 0,
            "requests": 2,
            "requestsallowed": 2,
            "requestsblocked": 0
        }
    }
}
```

#### Human Readable Output

>### Summary List
>|Application|Allowed Application|Blocked Application|Category|Domain|File|File Type|Identity|Identity Type|Policy Category|Policy Request|Request|Allowed Request|Blocked Request|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 0 | 0 | 4 | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 2 | 2 | 0 |


#### Command example
```!umbrella-reporting-summary-list summary_type=category limit=2 from=-30days to=now```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "SummaryWithCategory": [
            {
                "category": {
                    "deprecated": false,
                    "id": 148,
                    "integration": false,
                    "label": "Application",
                    "type": "application"
                },
                "summary": {
                    "applications": 0,
                    "applicationsallowed": 0,
                    "applicationsblocked": 0,
                    "categories": 70,
                    "domains": 1940,
                    "files": 1,
                    "filetypes": 0,
                    "identities": 3,
                    "identitytypes": 2,
                    "policycategories": 1,
                    "policyrequests": 0,
                    "requests": 30589,
                    "requestsallowed": 30453,
                    "requestsblocked": 80
                }
            },
            {
                "category": {
                    "deprecated": true,
                    "id": 25,
                    "integration": false,
                    "label": "Software/Technology",
                    "type": "content"
                },
                "summary": {
                    "applications": 0,
                    "applicationsallowed": 0,
                    "applicationsblocked": 0,
                    "categories": 58,
                    "domains": 1375,
                    "files": 0,
                    "filetypes": 0,
                    "identities": 3,
                    "identitytypes": 2,
                    "policycategories": 1,
                    "policyrequests": 0,
                    "requests": 26719,
                    "requestsallowed": 26675,
                    "requestsblocked": 16
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Summary with Category List
>|Category Type|Category Name|Application|Allowed Application|Blocked Application|Category|Domain|File|File Type|Identity|Identity Type|Policy Category|Policy Request|Request|Allowed Request|Blocked Request|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| application | Application | 0 | 0 | 0 | 70 | 1940 | 1 | 0 | 3 | 2 | 1 | 0 | 30589 | 30453 | 80 |
>| content | Software/Technology | 0 | 0 | 0 | 58 | 1375 | 0 | 0 | 3 | 2 | 1 | 0 | 26719 | 26675 | 16 |


#### Command example
```!umbrella-reporting-summary-list summary_type=destination limit=2 from=-30days to=now```
#### Context Example
```json
{
    "UmbrellaReporting": {
        "SummaryWithDestination": [
            {
                "domain": "www.cisco.com",
                "summary": {
                    "applications": 0,
                    "applicationsallowed": 0,
                    "applicationsblocked": 0,
                    "categories": 5,
                    "domains": 1,
                    "files": 0,
                    "filetypes": 0,
                    "identities": 3,
                    "identitytypes": 2,
                    "policycategories": 0,
                    "policyrequests": 0,
                    "requests": 1098,
                    "requestsallowed": 1098,
                    "requestsblocked": 0
                }
            },
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
                    "identities": 3,
                    "identitytypes": 2,
                    "policycategories": 0,
                    "policyrequests": 0,
                    "requests": 1034,
                    "requestsallowed": 1034,
                    "requestsblocked": 0
                }
            },
            {
                "domain": "x1.c.lencr.org",
                "summary": {
                    "applications": 0,
                    "applicationsallowed": 0,
                    "applicationsblocked": 0,
                    "categories": 1,
                    "domains": 1,
                    "files": 0,
                    "filetypes": 0,
                    "identities": 1,
                    "identitytypes": 1,
                    "policycategories": 0,
                    "policyrequests": 0,
                    "requests": 39,
                    "requestsallowed": 39,
                    "requestsblocked": 0
                }
            },
            {
                "domain": "download.anydesk.com",
                "summary": {
                    "applications": 0,
                    "applicationsallowed": 0,
                    "applicationsblocked": 0,
                    "categories": 2,
                    "domains": 1,
                    "files": 1,
                    "filetypes": 0,
                    "identities": 1,
                    "identitytypes": 1,
                    "policycategories": 0,
                    "policyrequests": 0,
                    "requests": 2,
                    "requestsallowed": 2,
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
>| www.cisco.com | 0 | 0 | 0 | 5 | 1 | 0 | 0 | 3 | 2 | 0 | 0 | 1098 | 1098 | 0 |
>| presence.teams.microsoft.com | 0 | 0 | 0 | 6 | 1 | 0 | 0 | 3 | 2 | 0 | 0 | 1034 | 1034 | 0 |
>| x1.c.lencr.org | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 39 | 39 | 0 |
>| download.anydesk.com | 0 | 0 | 0 | 2 | 1 | 1 | 0 | 1 | 1 | 0 | 0 | 2 | 2 | 0 |


#### Command example
```!umbrella-reporting-summary-list summary_type=intrusion_rule limit=2 from=-30days to=now```
#### Human Readable Output

>UmbrellaReporting does not have intrusion_rule summary to present. 

