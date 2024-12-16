## Overview

Dataminr Pulse brings the most advanced AI-powered real-time intelligence into Cortex XSOAR, easily fitting into your workflows and enabling rapid identification and mitigation of emerging threats so you can deliver faster time to detection and response.

#### Swiftly Close The Loop From Insight to Response

Effectively detect, prioritize and manage risk to protect your physical and digital assets with the fastest real-time alerting to discover threats as they unfold.

#### Broad Global Threat Coverage at Unmatched AI Speed

Dataminr has been the global leader in AI for risk detection since 2009. Dataminr Pulse is relied on by two thirds of Fortune 100 companies to inform their physical and cybersecurity operations. Every day, the Dataminr multi-modal AI platform analyzes billions of public data inputs in 105 languages from over 500K global sources including the deep and dark web, enabling you to:

- Gain real-time visibility into deep and dark web sources including markets, forums, paste sites, and ransomware group sites.
- Get first notice on emerging attacks impacting your network and third parties affecting your business.
- Detect risk at a global scale and track the emergence and global spread of vulnerabilities so you can proactively mitigate risk.
- Identify new ransomware groups and track attacks as they happen, giving you visibility of attacks impacting your or third party risk perspective.

#### Pulse for Cyber Risk Key Use Cases

- Cyber-Physical Convergence: Gain real-time intelligence on converged cyber and physical threats, including physical threats to IT and OT infrastructure, network and power outages, disasters, and emerging geopolitical risks.
- Vulnerability Prioritization: Prioritize patching with visibility to the entire lifecycle of a vulnerability, from pre-CVE to exploitation, while surfacing relevant vulnerabilities in your infrastructure.
- External Attack Intelligence: Mitigate risk by tracking threats to your company, subsidiaries, and 3rd parties across ransomware, APT groups, leaks, breaches, DDoS, defacement, and malware activity.
- Digital Risk Detection: Get early warnings of risk to digital assets, including leaked credentials and data, account and domain impersonation, and mentions across the surface deep and dark web.

#### Accelerate and Enrich SOC Workflows

- Accelerate, enrich and trigger triage with contextual intelligence
- Activate playbooks
- Improve incident investigation and response
- Support analysis and threat hunting workflows
- Determine threat identification, scoring and classification by type, severity and status

## Use cases

1. #### Alert Ingestion

    Fetches the Dataminr Alerts as an XSOAR Incident based on the configuration parameters. This will have three filters available in place.
   1) Watchlist Names
   2) Query
   3) Alert type (severity)

2. #### Alert Enrichment

    Use playbook `Retrieve Alerts For IOCs - Dataminr Pulse` to enrich XSOAR incidents using Dataminr Alerts.
   - This playbook requires three parameters:
     1) Text to enrich
     2) Number of alerts to retrieve for each indicator
     3) A boolean to use configured watchlist names
   - This playbook will extract indicators from given text (default will be entire incident context).
   - After that it will retrieve alerts for each indicator and will store those alerts into context with key `RetrievedDataminrAlerts`.

## Configure Dataminr Pulse in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Client ID | The Client ID required to authenticate to the service. | True |
| Client Secret | The Client Secret required to authenticate to the service. | True |
| Watchlist Names | A comma-separated string of watchlist names, from which to fetch the alerts. If not provided, then it will fetch alerts from all available watchlists on the platform. | False |
| Query | Terms to search within Dataminr Alerts. | False |
| Alert Type | Filters the incoming alerts with the provided alert type. Default All. | False |
| Max Fetch | The maximum number of alerts to fetch each time. If the value is greater than 200, it will be considered as 200. The maximum is 200. | False |
| Trust any certificate (not secure) | Indicates whether to allow connections without verifying the SSL certificate's validity. | False |
| Use system proxy settings | Indicates whether to use XSOAR's system proxy settings to connect to the API. | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval | The incident fetch interval. | False |
| First Fetch Time (not supported) | This parameter is not supported as Dataminr Pulse API doesn't have time based filtering for fetching of alerts. | False |



#### Note

1. If you detach the out-of-the-box mapper and make changes to it, the pack does not automatically get updates.
   - If you are using a custom incident type, you also need to create custom corresponding incoming mappers.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dataminrpulse-watchlists-get

***
Retrieves the Watchlists configured on the Dataminr platform.

#### Base Command

`dataminrpulse-watchlists-get`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DataminrPulse.WatchLists.id | Number | Unique identifier for an individual list. This ID is needed to retrieve alerts for a given list. | 
| DataminrPulse.WatchLists.type | String | Type of list. Can be one of the Topic, Company, or Custom. | 
| DataminrPulse.WatchLists.name | String | Name of list as specified in Dataminr platform. | 
| DataminrPulse.WatchLists.description | String | Description of the list as specified in Dataminr platform. | 
| DataminrPulse.WatchLists.properties.watchlistColor | String | Watchlist color chosen within the Dataminr platform. | 
| DataminrPulse.WatchLists.companies.id | String | ID of the company. | 
| DataminrPulse.WatchLists.companies.name | String | Name of the company. | 

#### Command example
```!dataminrpulse-watchlists-get```
#### Context Example
```json
{
    "DataminrPulse": {
        "WatchLists": [
            {
                "description": "",
                "id": 3320156,
                "name": "Cyber-Physical",
                "properties": {
                    "watchlistColor": "darkblue"
                },
                "type": "TOPIC"
            },
            {
                "description": "",
                "id": 3320155,
                "name": "Data Security",
                "properties": {
                    "watchlistColor": "red"
                },
                "type": "TOPIC"
            }
        ]
    }
}
```

#### Human Readable Output

>### Watchlists
>|Watchlist ID|Watchlist Name|Watchlist Type|Watchlist Color|
>|---|---|---|---|
>| 3320156 | Cyber-Physical | TOPIC | darkblue |
>| 3320155 | Data Security | TOPIC | red |


### dataminrpulse-alerts-get

***
Retrieves the alerts as per the provided watchlist_ids or query or configured watchlist_names parameter in integration. Note: The "from" and "to" arguments should not be included on the first execution, there will not be any "from" or "to" cursor to reference. Only subsequent calls should contain those parameters.

#### Base Command

`dataminrpulse-alerts-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_ids | Comma delimited set of watchlist IDs. Required if watchlist names are not configured in integration configuration and the query is not given. | Optional | 
| query | Terms to search within Dataminr Alerts. Required if watchlist names are not configured in integration configuration and the watchlist_ids are not given. | Optional | 
| from | It points to a cursor that you want any alerts after. Note that only one of "from" or "to" can be included per request. | Optional | 
| to | It points to a cursor that you want any alerts before. Note that only one of "from" and "to" can be included per request. | Optional | 
| num | Maximum number of alerts to return. 3333 is maximum value. Default is 40. | Optional | 
| use_configured_watchlist_names | A Boolean indicating that If user does not provide watchlist IDs then it should use configured watchlist names with query parameter. Possible values are: yes, no. Default is yes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DataminrPulse.Alerts.alertId | String | Unique ID of the alert. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.id | String | Unique ID of the watchlist. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.type | String | Type of the watchlist. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.name | String | Name of the watchlist. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.externalTopicIds | String | String containing the ID of external topic for watchlist type. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.userProperties.omnilist | String | String containing the boolean value of omnilist. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.userProperties.uiListType | String | Type of the watchlist on the Dataminr platform. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.userProperties.watchlistColor | String | Color of the watchlist defined on the Dataminr platform. | 
| DataminrPulse.Alerts.availableRelatedAlerts | String | Whether the alert has related alerts or not. | 
| DataminrPulse.Alerts.eventTime | Number | Timestamp of the event. | 
| DataminrPulse.Alerts.eventVolume | Number | Volume of the event. | 
| DataminrPulse.Alerts.eventLocation.coordinates | Unknown | Latitude and Longitude of the event. | 
| DataminrPulse.Alerts.eventLocation.name | String | The name of the place where the event occurred. | 
| DataminrPulse.Alerts.eventLocation.places | Unknown | Place IDs of the event location. | 
| DataminrPulse.Alerts.eventLocation.radius | Number | Radius of the event location. | 
| DataminrPulse.Alerts.source.displayName | String | The display name of the source. | 
| DataminrPulse.Alerts.source.entityName | String | The entity name of the source. | 
| DataminrPulse.Alerts.source.verified | Boolean | True if the source is verified, false otherwise. | 
| DataminrPulse.Alerts.source.channels | Unknown | The Dataminr channel to which the source belongs. | 
| DataminrPulse.Alerts.post.timestamp | Number | The timestamp of the post. | 
| DataminrPulse.Alerts.post.languages.position | Number | The position of the post. | 
| DataminrPulse.Alerts.post.languages.lang | String | The language of the post. | 
| DataminrPulse.Alerts.post.media.type | String | The type of the media. | 
| DataminrPulse.Alerts.post.media.url | String | The URL of the media. | 
| DataminrPulse.Alerts.post.media.description | String | The description of the media. | 
| DataminrPulse.Alerts.post.media.display_url | String | The display URL of the media. | 
| DataminrPulse.Alerts.post.media.media_url | String | The URL of the media. | 
| DataminrPulse.Alerts.post.media.source | String | The source of the media. | 
| DataminrPulse.Alerts.post.link | String | The link to the post. | 
| DataminrPulse.Alerts.caption | String | The text of the alert. | 
| DataminrPulse.Alerts.categories.name | String | The name of the category to which the alert belongs. | 
| DataminrPulse.Alerts.categories.topicType | String | The type of the Dataminr entity. Its value will be "category". | 
| DataminrPulse.Alerts.categories.id | String | The unique identifier of the category. | 
| DataminrPulse.Alerts.categories.idStr | String | The string value of the ID for the category. | 
| DataminrPulse.Alerts.categories.requested | String | String containing the boolean value for a category. | 
| DataminrPulse.Alerts.categories.path | String | The path of the Dataminr category. | 
| DataminrPulse.Alerts.categories.retired | Boolean | Boolean value of retired for a particular category. | 
| DataminrPulse.Alerts.headerColor | String | The hex value of the alert's header color. | 
| DataminrPulse.Alerts.headerLabel | String | The label of the alert's header. | 
| DataminrPulse.Alerts.alertType.id | String | The unique identifier of the alert type. | 
| DataminrPulse.Alerts.alertType.name | String | The name of the alert type. | 
| DataminrPulse.Alerts.alertType.color | String | The color of alert type. | 
| DataminrPulse.Alerts.publisherCategory.id | String | The unique identifier of the publisher category. | 
| DataminrPulse.Alerts.publisherCategory.name | String | The name of the publisher category. | 
| DataminrPulse.Alerts.publisherCategory.color | String | The color of the publisher category. | 
| DataminrPulse.Alerts.publisherCategory.shortName | String | The short name for publisher category. | 
| DataminrPulse.Alerts.eventMapSmallURL | String | Value containing the URL of the small event map image. | 
| DataminrPulse.Alerts.eventMapLargeURL | String | Value containing the URL of the large event map image. | 
| DataminrPulse.Alerts.expandAlertURL | String | URL of the alert details page. | 
| DataminrPulse.Alerts.expandMapURL | String | URL of the expanded map. | 
| DataminrPulse.Alerts.relatedTerms.text | String | Text of the related terms. | 
| DataminrPulse.Alerts.relatedTerms.url | String | URL of the related terms. | 
| DataminrPulse.Alerts.relatedTermsQueryURL | String | URL of the related terms query. | 
| DataminrPulse.Alerts.parentAlertId | String | Alert ID of the parent. | 
| DataminrPulse.Alerts.metadata.cyber.URLs | Unknown | Identifier for a specific part of a website referenced in posts that could be related to a target or attacker's infrastructure. | 
| DataminrPulse.Alerts.metadata.cyber.threats | Unknown | Name of cyber threat. | 
| DataminrPulse.Alerts.metadata.cyber.addresses.ip | String | IP address of attacker/victim. Note that IP can have more than one open port and ports are associated with specific products via IANA \(iana.org\). | 
| DataminrPulse.Alerts.metadata.cyber.addresses.port | Number | Port of attacker/victim. | 
| DataminrPulse.Alerts.metadata.cyber.addresses.version | String | Version of IP address. | 
| DataminrPulse.Alerts.metadata.cyber.asns | Unknown | Name of the autonomous systems number of the company hosting the impacted service\(s\). | 
| DataminrPulse.Alerts.metadata.cyber.orgs | Unknown | Name of the ASN \(company hosting the impacted service\). | 
| DataminrPulse.Alerts.metadata.cyber.products | Unknown | The server software used on an IP address. | 
| DataminrPulse.Alerts.metadata.cyber.hashes | Unknown | A unique identifier or fingerprint for a file, often a malicious executable. | 
| DataminrPulse.Alerts.metadata.cyber.malwares | Unknown | Malicious software posing a threat. | 
| DataminrPulse.Alerts.metadata.cyber.asOrgs.asn | String | Autonomous system number. | 
| DataminrPulse.Alerts.metadata.cyber.asOrgs.asOrg | String | Autonomous system organization. | 
| DataminrPulse.Alerts.metadata.cyber.hashValues.value | String | Hash value. | 
| DataminrPulse.Alerts.metadata.cyber.hashValues.type | String | Hash value type. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.id | String | CVE ID. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.cvss | String | CVSS value. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.exploitPocLinks | Unknown | Exploited PoC links. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.products.productName | String | Product name. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.products.productVersion | String | Product version. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.products.productVendor | String | Product vendor. | 
| DataminrPulse.Alerts.companies.name | String | The name of the company. | 
| DataminrPulse.Alerts.companies.topicType | String | The type of the Dataminr entity. Its value will be "company". | 
| DataminrPulse.Alerts.companies.id | String | The unique identifier of the company. | 
| DataminrPulse.Alerts.companies.idStr | String | The string value of the ID for the company. | 
| DataminrPulse.Alerts.companies.ticker | String | The ticker symbol of the company. | 
| DataminrPulse.Alerts.companies.retired | Boolean | Boolean value of retired for a particular company. | 
| DataminrPulse.Alerts.companies.dm_bucket.id | String | The ID of the Dataminr bucket to which the company belongs. | 
| DataminrPulse.Alerts.companies.dm_bucket.name | String | The name of the Dataminr bucket to which the company belongs. | 
| DataminrPulse.Alerts.companies.dm_sector.id | String | The ID of the Dataminr sector to which the company belongs. | 
| DataminrPulse.Alerts.companies.dm_sector.name | String | The name of the Dataminr sector to which the company belongs. | 
| DataminrPulse.Alerts.sectors.name | String | The name of the sector to which the alert belongs. | 
| DataminrPulse.Alerts.sectors.topicType | String | The type of the Dataminr entity. Its value will be "dm_sector". | 
| DataminrPulse.Alerts.sectors.id | String | The unique identifier of the sector. | 
| DataminrPulse.Alerts.sectors.idStr | String | The string value of the ID for the sector. | 
| DataminrPulse.Alerts.sectors.retired | Boolean | Boolean value of retired for sectors. | 
| DataminrPulse.Alerts.subCaption.bullets.source | String | Source from which information about Dataminr events is obtained. | 
| DataminrPulse.Alerts.subCaption.bullets.media | String | Media from information about Dataminr event derived exclusively from the attributed source. | 
| DataminrPulse.Alerts.subCaption.bullets.content | String | Content from information about Dataminr event derived exclusively from the attributed source. | 
| DataminrPulse.Alerts.userRecentImages | Unknown | User's recent images. | 
| DataminrPulse.Alerts.userTopHashtags | Unknown | User's top hashtags. | 
| DataminrPulse.Cursor.from | String | "from" points to a cursor that you want any alerts after. | 
| DataminrPulse.Cursor.to | String | "to" points to a cursor that you want any alerts before. | 

#### Command example
```!dataminrpulse-alerts-get query="Google" num=2 use_configured_watchlist_names=yes```
#### Context Example
```json
{
    "DataminrPulse": {
        "Alerts": [
            {
                "alertId": "263446797171227825118793783-1679036084482-1",
                "alertType": {
                    "color": "FFBB05",
                    "id": "alert",
                    "name": "Alert"
                },
                "availableRelatedAlerts": 0,
                "caption": "Credentials from Netflix, Roku and Google in post selling data from machine infected by Raccoon stealer in United States: Blog via Russian Market.",
                "categories": [
                    {
                        "id": "853086",
                        "idStr": "853086",
                        "name": "Cybersecurity - Threats & Vulnerabilities",
                        "path": "/TOPIC/EXT/CS/853086",
                        "retired": false,
                        "topicType": "category"
                    },
                    {
                        "id": "853084",
                        "idStr": "853084",
                        "name": "Cybersecurity - Crime & Malicious Activity",
                        "path": "/TOPIC/EXT/CS/853084",
                        "retired": false,
                        "topicType": "category"
                    },
                ],
                "companies": [
                    {
                        "id": "1e8efb6d2c02a70af5041088361f83f3",
                        "idStr": "1e8efb6d2c02a70af5041088361f83f3",
                        "name": "Netflix, Inc.",
                        "retired": false,
                        "ticker": "NFLX",
                        "topicType": "company"
                    },
                    {
                        "id": "5936d9ec1bfbafc7a6ebb01d32d58855",
                        "idStr": "5936d9ec1bfbafc7a6ebb01d32d58855",
                        "name": "Google LLC",
                        "requested": "true",
                        "retired": false,
                        "topicType": "company"
                    }
                ],
                "eventLocation": {
                    "coordinates": [
                        18.889333,
                        -27
                    ],
                    "name": "united states",
                    "places": [
                        "0854a181a37b433c8e76fbca8d5101cf",
                        "f66b10a1b6d5d260b3ddb7e7518aa5ac"
                    ],
                    "probability": 0,
                    "radius": 0
                },
                "eventMapLargeURL": "https://api.dataminr.com/images/1/map?size=540x124",
                "eventMapSmallURL": "https://api.dataminr.com/images/1/map?size=124x124",
                "eventTime": 1679036084484,
                "eventVolume": 0,
                "expandAlertURL": "https://app.dataminr.com/#alertDetail/5/263446797171227825118793783-1679036084482-1",
                "expandMapURL": "https://app.dataminr.com/#map-popup2/",
                "headerColor": "FFFFAD",
                "headerLabel": "Alert",
                "post": {
                    "link": "http://dummy.com/logs#b557780d27d99",
                    "timestamp": 1678924800000
                },
                "publisherCategory": {
                    "color": "6596c8",
                    "id": "blog",
                    "name": "Blog",
                    "shortName": "BG"
                },
                "relatedTerms": [
                    {
                        "text": "stealer",
                        "url": "https://app.dataminr.com/app/core/corporate/search-popup.html#search/stealer"
                    },
                    {
                        "text": "tech hardware",
                        "url": "https://app.dataminr.com/app/core/corporate/search-popup.html#search/hardware"
                    },
                    {
                        "text": "tech media",
                        "url": "https://app.dataminr.com/app/core/corporate/search-popup.html#search/media"
                    }
                ],
                "relatedTermsQueryURL": "https://app.dataminr.com/#search-popup/search/electronics",
                "sectors": [
                    {
                        "id": "ba46e75a7aefcb7e152b31aebae04d36",
                        "idStr": "ba46e75a7aefcb7e152b31aebae04d36",
                        "name": "Hardware",
                        "retired": false,
                        "topicType": "dm_sector"
                    }
                ],
                "source": {
                    "channels": [
                        "blog"
                    ],
                    "verified": false
                },
                "watchlistsMatchedByType": [
                    {
                        "externalTopicIds": [
                            "961957",
                            "961960"
                        ],
                        "id": "3320155",
                        "name": "Data Security",
                        "type": "topics",
                        "userProperties": {
                            "omnilist": "true",
                            "uiListType": "CYBER",
                            "watchlistColor": "red"
                        }
                    }
                ]
            },
            {
                "alertId": "8182773200381469871601567489-1679036084274-1",
                "alertType": {
                    "color": "FFBB05",
                    "id": "alert",
                    "name": "Alert"
                },
                "availableRelatedAlerts": 0,
                "caption": "Credentials from Google and Paypal in post selling data from machine infected by Raccoon stealer in Venezuela: Blog via Russian Market.",
                "categories": [
                    {
                        "id": "853086",
                        "idStr": "853086",
                        "name": "Cybersecurity - Threats & Vulnerabilities",
                        "path": "/TOPIC/EXT/CS/853086",
                        "retired": false,
                        "topicType": "category"
                    },
                    {
                        "id": "853084",
                        "idStr": "853084",
                        "name": "Cybersecurity - Crime & Malicious Activity",
                        "path": "/TOPIC/EXT/CS/853084",
                        "retired": false,
                        "topicType": "category"
                    },
                    {
                        "id": "962012",
                        "idStr": "962012",
                        "name": "Hacking Services",
                        "path": "/TOPIC/EXT/CS/962012",
                        "retired": false,
                        "topicType": "category"
                    }
                ],
                "companies": [
                    {
                        "id": "5936d9ec1bfbafc7a6ebb01d32d58855",
                        "idStr": "5936d9ec1bfbafc7a6ebb01d32d58855",
                        "name": "Google LLC",
                        "requested": "true",
                        "retired": false,
                        "topicType": "company"
                    },
                    {
                        "id": "cb5aa0e62a22c02eea509f4ed369f97e",
                        "idStr": "cb5aa0e62a22c02eea509f4ed369f97e",
                        "name": "PayPal Holdings, Inc.",
                        "retired": false,
                        "ticker": "PYPL",
                        "topicType": "company"
                    }
                ],
                "eventLocation": {
                    "coordinates": [
                        50.18333333,
                        -26.366667
                    ],
                    "name": "Venezuela",
                    "places": [
                        "2c6646409a5244a0ac9ca02c0c134cbf",
                        "65e310f6bf1662b763071ef967f60781"
                    ],
                    "probability": 0,
                    "radius": 0
                },
                "eventMapLargeURL": "https://api.dataminr.com/images/1/map?size=540x124",
                "eventMapSmallURL": "https://api.dataminr.com/images/1/map?size=124x124",
                "eventTime": 1679032084075,
                "eventVolume": 0,
                "expandAlertURL": "https://app.dataminr.com/#alertDetail/5/8182773200381469871601567489-1679036084274-1",
                "expandMapURL": "https://app.dataminr.com/#map-popup2/",
                "headerColor": "FFFFAD",
                "headerLabel": "Alert",
                "post": {
                    "link": "http://dummy.com/logs#b05eb146256c7774f",
                    "timestamp": 1608924200000
                },
                "publisherCategory": {
                    "color": "6596c8",
                    "id": "blog",
                    "name": "Blog",
                    "shortName": "BG"
                },
                "relatedTerms": [
                    {
                        "text": "credentials",
                        "url": "https://app.dataminr.com/app/core/corporate/search-popup.html#search/elements"
                    },
                    {
                        "text": "cyber markets",
                        "url": "https://app.dataminr.com/app/core/corporate/search-popup.html#search/cyber"
                    },
                    {
                        "text": "data exposures",
                        "url": "https://app.dataminr.com/app/core/corporate/search-popup.html#search/exposures"
                    }
                ],
                "relatedTermsQueryURL": "https://app.dataminr.com/#search-popup/search/cyber markets,data exposures",
                "sectors": [
                    {
                        "id": "8d8dfe15852996c0f6881b32",
                        "idStr": "8d8dfe15852996c0f6881b32",
                        "name": "Software",
                        "retired": false,
                        "topicType": "dm_sector"
                    }
                ],
                "source": {
                    "channels": [
                        "blog"
                    ],
                    "verified": false
                },
                "watchlistsMatchedByType": [
                    {
                        "externalTopicIds": [
                            "961957",
                            "961960"
                        ],
                        "id": "3320155",
                        "name": "Data Security",
                        "type": "topics",
                        "userProperties": {
                            "omnilist": "true",
                            "uiListType": "CYBER",
                            "watchlistColor": "red"
                        }
                    }
                ]
            }
        ],
        "Cursor": {
            "from": "from_cursor",
            "to": "to_cursor"
        }
    }
}
```

#### Human Readable Output

>### Alerts
>|Alert Type|Alert ID|Caption|Alert URL|Watchlist Name|Alert Time|Alert Location|Post Link|Is source verified|Publisher Category|
>|---|---|---|---|---|---|---|---|---|---|
>| Alert | 263446797171227825118793783-1679036084482-1 | Credentials from Netflix, Roku and Google in post selling data from machine infected by Raccoon stealer in United States: Blog via Russian Market. | [https://app.dataminr.com/#alertDetail/5/263446797171227825118793783-1679036084482-1](https://app.dataminr.com/#alertDetail/5/263446797171227825118793783-1679036084482-1) | Data Security | 17 Mar 2023, 06:54 AM UTC | united states | [http://dummy.com/logs#b557780d27d99](http://dummy.com/logs#b557780d27d99) | false | Blog |
>| Alert | 8182773200381469871601567489-1679036084274-1 | Credentials from Google and Paypal in post selling data from machine infected by Raccoon stealer in Venezuela: Blog via Russian Market. | [https://app.dataminr.com/#alertDetail/5/8182773200381469871601567489-1679036084274-1](https://app.dataminr.com/#alertDetail/5/8182773200381469871601567489-1679036084274-1) | Data Security | 17 Mar 2023, 06:54 AM UTC | venezuela | [http://dummy.com/logs#b05eb146256c7774f](http://dummy.com/logs#b05eb146256c7774f) | false | Blog |

>### Cursor for pagination
>|from|to|
>|---|---|
>| from_cursor | to_cursor |

### dataminrpulse-related-alerts-get

***
Retrieves the alerts related to the provided Alert ID.

#### Base Command

`dataminrpulse-related-alerts-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Unique identifier of the alert whose related alerts to retrieve. | Required | 
| include_root | When searching for a linked cluster, this flag<br/>determines whether the alert from which alert_id is used to make request to the server is returned to the result set. Possible values are: False, True. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DataminrPulse.Alerts.alertId | String | Unique ID of the alert. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.id | String | Unique ID of the watchlist. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.type | String | Type of the watchlist. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.name | String | Name of the watchlist. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.externalTopicIds | String | String containing the ID of external topic for watchlist type. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.userProperties.omnilist | String | String containing the boolean value of omnilist. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.userProperties.uiListType | String | Type of the watchlist on the Dataminr platform. | 
| DataminrPulse.Alerts.watchlistsMatchedByType.userProperties.watchlistColor | String | Color of the watchlist defined on the Dataminr platform. | 
| DataminrPulse.Alerts.availableRelatedAlerts | String | Whether the alert has related alerts or not. | 
| DataminrPulse.Alerts.eventTime | Number | Timestamp of the event. | 
| DataminrPulse.Alerts.eventVolume | Number | Volume of the event. | 
| DataminrPulse.Alerts.eventLocation.coordinates | Unknown | Latitude and Longitude of the event. | 
| DataminrPulse.Alerts.eventLocation.name | String | The name of the place where the event occurred. | 
| DataminrPulse.Alerts.eventLocation.places | Unknown | Place IDs of the event location. | 
| DataminrPulse.Alerts.eventLocation.radius | Number | Radius of the event location. | 
| DataminrPulse.Alerts.source.displayName | String | The display name of the source. | 
| DataminrPulse.Alerts.source.entityName | String | The entity name of the source. | 
| DataminrPulse.Alerts.source.verified | Boolean | True if the source is verified, false otherwise. | 
| DataminrPulse.Alerts.source.channels | Unknown | The Dataminr channel to which the source belongs. | 
| DataminrPulse.Alerts.post.timestamp | Number | The timestamp of the post. | 
| DataminrPulse.Alerts.post.languages.position | Number | The position of the post. | 
| DataminrPulse.Alerts.post.languages.lang | String | The language of the post. | 
| DataminrPulse.Alerts.post.media.type | String | The type of the media. | 
| DataminrPulse.Alerts.post.media.url | String | The URL of the media. | 
| DataminrPulse.Alerts.post.media.description | String | The description of the media. | 
| DataminrPulse.Alerts.post.media.display_url | String | The display URL of the media. | 
| DataminrPulse.Alerts.post.media.media_url | String | The URL of the media. | 
| DataminrPulse.Alerts.post.media.source | String | The source of the media. | 
| DataminrPulse.Alerts.post.link | String | The link to the post. | 
| DataminrPulse.Alerts.caption | String | The text of the alert. | 
| DataminrPulse.Alerts.categories.name | String | The name of the category to which the alert belongs. | 
| DataminrPulse.Alerts.categories.topicType | String | The type of the Dataminr entity. Its value will be "category". | 
| DataminrPulse.Alerts.categories.id | String | The unique identifier of the category. | 
| DataminrPulse.Alerts.categories.idStr | String | The string value of the ID for the category. | 
| DataminrPulse.Alerts.categories.requested | String | String containing the boolean value for a category. | 
| DataminrPulse.Alerts.categories.path | String | The path of the Dataminr category. | 
| DataminrPulse.Alerts.categories.retired | Boolean | Boolean value of retired for a particular category. | 
| DataminrPulse.Alerts.headerColor | String | The hex value of the alert's header color. | 
| DataminrPulse.Alerts.headerLabel | String | The label of the alert's header. | 
| DataminrPulse.Alerts.alertType.id | String | The unique identifier of the alert type. | 
| DataminrPulse.Alerts.alertType.name | String | The name of the alert type. | 
| DataminrPulse.Alerts.alertType.color | String | The color of alert type. | 
| DataminrPulse.Alerts.publisherCategory.id | String | The unique identifier of the publisher category. | 
| DataminrPulse.Alerts.publisherCategory.name | String | The name of the publisher category. | 
| DataminrPulse.Alerts.publisherCategory.color | String | The color of the publisher category. | 
| DataminrPulse.Alerts.publisherCategory.shortName | String | The short name for publisher category. | 
| DataminrPulse.Alerts.eventMapSmallURL | String | Value containing the URL of the small event map image. | 
| DataminrPulse.Alerts.eventMapLargeURL | String | Value containing the URL of the large event map image. | 
| DataminrPulse.Alerts.expandAlertURL | String | URL of the alert details page. | 
| DataminrPulse.Alerts.expandMapURL | String | URL of the expanded map. | 
| DataminrPulse.Alerts.relatedTerms.text | String | Text of the related terms. | 
| DataminrPulse.Alerts.relatedTerms.url | String | URL of the related terms. | 
| DataminrPulse.Alerts.relatedTermsQueryURL | String | URL of the related terms query. | 
| DataminrPulse.Alerts.parentAlertId | String | Alert ID of the parent. | 
| DataminrPulse.Alerts.metadata.cyber.URLs | Unknown | Identifier for a specific part of a website referenced in posts that could be related to a target or attacker's infrastructure. | 
| DataminrPulse.Alerts.metadata.cyber.threats | Unknown | Name of cyber threat. | 
| DataminrPulse.Alerts.metadata.cyber.addresses.ip | String | IP address of attacker/victim. Note that IP can have more than one open port and ports are associated with specific products via IANA \(iana.org\). | 
| DataminrPulse.Alerts.metadata.cyber.addresses.port | Number | Port of attacker/victim. | 
| DataminrPulse.Alerts.metadata.cyber.addresses.version | String | Version of IP address. | 
| DataminrPulse.Alerts.metadata.cyber.asns | Unknown | Name of the autonomous systems number of the company hosting the impacted service\(s\). | 
| DataminrPulse.Alerts.metadata.cyber.orgs | Unknown | Name of the ASN \(company hosting the impacted service\). | 
| DataminrPulse.Alerts.metadata.cyber.products | Unknown | The server software used on an IP address. | 
| DataminrPulse.Alerts.metadata.cyber.hashes | Unknown | A unique identifier or fingerprint for a file, often a malicious executable. | 
| DataminrPulse.Alerts.metadata.cyber.malwares | Unknown | Malicious software posing a threat. | 
| DataminrPulse.Alerts.metadata.cyber.asOrgs.asn | String | Autonomous system number. | 
| DataminrPulse.Alerts.metadata.cyber.asOrgs.asOrg | String | Autonomous system organization. | 
| DataminrPulse.Alerts.metadata.cyber.hashValues.value | String | Hash value. | 
| DataminrPulse.Alerts.metadata.cyber.hashValues.type | String | Hash value type. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.id | String | CVE ID. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.cvss | String | CVSS value. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.exploitPocLinks | Unknown | Exploited PoC links. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.products.productName | String | Product name. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.products.productVersion | String | Product version. | 
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.products.productVendor | String | Product vendor. | 
| DataminrPulse.Alerts.companies.name | String | The name of the company. | 
| DataminrPulse.Alerts.companies.topicType | String | The type of the Dataminr entity. Its value will be "company". | 
| DataminrPulse.Alerts.companies.id | String | The unique identifier of the company. | 
| DataminrPulse.Alerts.companies.idStr | String | The string value of the ID for the company. | 
| DataminrPulse.Alerts.companies.ticker | String | The ticker symbol of the company. | 
| DataminrPulse.Alerts.companies.retired | Boolean | Boolean value of retired for a particular company. | 
| DataminrPulse.Alerts.companies.dm_bucket.id | String | The ID of the Dataminr bucket to which the company belongs. | 
| DataminrPulse.Alerts.companies.dm_bucket.name | String | The name of the Dataminr bucket to which the company belongs. | 
| DataminrPulse.Alerts.companies.dm_sector.id | String | The ID of the Dataminr sector to which the company belongs. | 
| DataminrPulse.Alerts.companies.dm_sector.name | String | The name of the Dataminr sector to which the company belongs. | 
| DataminrPulse.Alerts.sectors.name | String | The name of the sector to which the alert belongs. | 
| DataminrPulse.Alerts.sectors.topicType | String | The type of the Dataminr entity. Its value will be "dm_sector". | 
| DataminrPulse.Alerts.sectors.id | String | The unique identifier of the sector. | 
| DataminrPulse.Alerts.sectors.idStr | String | The string value of the ID for the sector. | 
| DataminrPulse.Alerts.sectors.retired | Boolean | Boolean value of retired for sectors. | 
| DataminrPulse.Alerts.subCaption.bullets.source | String | Source from which information about Dataminr events is obtained. | 
| DataminrPulse.Alerts.subCaption.bullets.media | String | Media from information about Dataminr event derived exclusively from the attributed source. | 
| DataminrPulse.Alerts.subCaption.bullets.content | String | Content from information about Dataminr event derived exclusively from the attributed source. | 
| DataminrPulse.Alerts.userRecentImages | Unknown | User's recent images. | 
| DataminrPulse.Alerts.userTopHashtags | Unknown | User's top hashtags. | 

#### Command example
```!dataminrpulse-related-alerts-get alert_id="969633949-1679028615394-3"```
#### Context Example
```json
{
    "DataminrPulse": {
        "Alerts": {
            "alertId": "1114146985-1679026540479-3",
            "alertType": {
                "color": "FFBB05",
                "id": "urgent",
                "name": "Urgent"
            },
            "caption": "Power outage affects 1,328 customers in Brisbane City, QLD, Australia: Government via Energex.",
            "categories": [
                {
                    "id": "853036",
                    "idStr": "853036",
                    "name": "Outages & Service Disruptions - Electricity",
                    "path": "/TOPIC/EXT/CS/853036",
                    "retired": false,
                    "topicType": "category"
                },
                {
                    "id": "726708",
                    "idStr": "726708",
                    "name": "Transportation & Infrastructure",
                    "path": "/TOPIC/EXT/CS/726708",
                    "retired": false,
                    "topicType": "category"
                }
            ],
            "eventLocation": {
                "coordinates": [
                    -17.4304528,
                    53.0200341
                ],
                "name": "Brisbane City QLD 4000, Australia",
                "places": [
                    "0a86c104be134cc39c098cd49adab0eb",
                    "433e1412080ffa35aba6fe6eb4b99c38",
                ],
                "radius": 1.0532969379634942
            },
            "eventMapLargeURL": "https://api.dataminr.com/images/1/map?size=540x124",
            "eventMapSmallURL": "https://api.dataminr.com/images/1/map?size=124x124",
            "eventTime": 1679026576914,
            "eventVolume": 0,
            "expandAlertURL": "https://app.dataminr.com/#alertDetail/5/1114146985-1679026540479-3",
            "expandMapURL": "https://app.dataminr.com/#map-popup2",
            "headerColor": "FFFFAD",
            "headerLabel": "Urgent",
            "post": {
                "link": "https://www.dummy.com/residential-and-business/power-interruptions/current-interruptions",
                "timestamp": 1679029576914
            },
            "publisherCategory": {
                "color": "5C0F07",
                "id": "gov",
                "name": "Government",
                "shortName": "GOV"
            },
            "relatedTerms": [
                {
                    "text": "affects",
                    "url": "https://app.dataminr.com/app/core/corporate/search-popup.html#search/history"
                },
                {
                    "text": "brisbane",
                    "url": "https://app.dataminr.com/app/core/corporate/search-popup.html#search/displayTitle"
                },
                {
                    "text": "outage",
                    "url": "https://app.dataminr.com/app/core/corporate/search-popup.html#search/history"
                }
            ],
            "relatedTermsQueryURL": "https://app.dataminr.com/#search-popup/search/affects,brisbane,outage,qld",
            "source": {
                "channels": [
                    "gov"
                ],
                "verified": false
            }
        }
    }
}
```

#### Human Readable Output

>### Alerts
>|Alert Type|Alert ID|Caption|Alert URL|Alert Time|Alert Location|Post Link|Is source verified|Publisher Category|
>|---|---|---|---|---|---|---|---|---|
>| Urgent | 1114146985-1679026540479-3 | Power outage affects 1,328 customers in Brisbane City, QLD, Australia: Government via Energex. | [https://app.dataminr.com/#alertDetail/5/1114146985-1679026540479-3](https://app.dataminr.com/#alertDetail/5/1114146985-1679026540479-3) | 17 Mar 2023, 04:16 AM UTC | Brisbane City QLD 4000, Australia | [https://www.dummy.com/residential-and-business/power-interruptions/current-interruptions](https://www.dummy.com/residential-and-business/power-interruptions/current-interruptions) | false | Government |