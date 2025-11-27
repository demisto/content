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

## Configure Dataminr Pulse - ReGenAI in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Dataminr Pulse - ReGenAI.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Client ID | The Client ID required to authenticate to the service. | True |
| Client Secret | The Client Secret required to authenticate to the service. | True |
| Watchlist Names | Provide the watchlist names from which to fetch the alerts. If not provided, alerts will be fetched from all available watchlists on the platform. | False |
| Query | Terms to search within Dataminr Alerts. | False |
| Alert Type | Filters the incoming alerts with the provided alert type. Default All. | False |
| Max Fetch | The maximum number of alerts to fetch each time. If the value is greater than 100, it will be considered as 100. The maximum is 100. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Create relationships |  Create relationships between indicators as part of enrichment. | False |
| Trust any certificate (not secure) | Indicates whether to allow connections without verifying the SSL certificate's validity. | False |
| Use system proxy settings | Indicates whether to use XSOAR's system proxy settings to connect to the API. | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval | The incident fetch interval. | False |
| First Fetch Time (not supported) | This parameter is not supported as Dataminr Pulse API doesn't have time based filtering for fetching of alerts. | False |

4. Click **Test** to validate the URLs, token, and connection.

#### (Optional) Set up Google Maps in Cortex XSOAR to Display Alert Locations in the Incident Layout

1. In Google Cloud Platform, do the following:

    - Create a [Google Cloud Project](https://developers.google.com/maps/documentation/javascript/cloud-setup).
    - Enable APIs and Services (**API & Services>Dashboard> ENABLE APIS AND SERVICES**).
    - Enable **Maps JavaScript API**.
    - Create the [Maps JavaScript API key](https://developers.google.com/maps/documentation/javascript/get-api-key#creating-api-keys) ( **Credentials> CREATE CREDENTIALS>API key**).
    - Copy the Maps JavaScript API key.

2. Add the Maps JavaScript API key to Cortex XSOAR.

    - For XSOAR 6: Select **Settings > ABOUT > Troubleshooting > Add Server Configuration**.
    For XSOAR 8: Select **Settings & Info > Settings > Server Settings > Add Server Configuration**.
    - Add the following key and value:

      | Key | Value |
      | --- | --- |
      | `ui.google.api.key` | `<Maps JavaScript API key>` |

    - Click **Save**.

#### Note

1. If you detach the out-of-the-box mapper and make changes to it, the pack does not automatically get updates.
   - If you are using a custom incident type, you also need to create custom corresponding incoming mappers.

## Troubleshooting

#### Known Issue: Custom CVE Indicators being overridden by the default CVE Type in XSOAR 8

We created a custom indicator type "Dataminr Pulse Vulnerability Indicator" similar to "CVE" so we can show the additional fields in our customized layout.
These indicators are extracted from Dataminr Pulse ReGenAI Alerts, but some of them are still being assigned the default "CVE" indicator type instead of our custom "Dataminr Pulse Vulnerability Indicator".

##### Tips for Handling the Issue

Manually edit the indicators type from **CVE** to **Dataminr Pulse Vulnerability Indicator** that were enriched by Dataminr Pulse ReGenAI Alert.

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
| DataminrPulse.WatchLists.id | Number | An unique identifier for an individual list. This ID is needed to retrieve alerts for a given list. |
| DataminrPulse.WatchLists.type | String | The type of list. Can be one of the Topic, Company, or Custom. |
| DataminrPulse.WatchLists.name | String | The name of list as specified in Dataminr platform. |
| DataminrPulse.WatchLists.subType | String | The sub type of list as specified in Dataminr platform. |

#### Command example

```!dataminrpulse-watchlists-get```

#### Context Example

```json
{
    "DataminrPulse": {
        "WatchLists": [
            {
               "id": 1,
               "name": "Attack Vendor",
               "type": "TOPIC",
               "subType": "CYBER"
            },
            {
               "id": 2,
               "name": "Cyber-Physical",
               "type": "TOPIC",
               "subType": "VULNERABILITY"
            }
        ]
    }
}
```

#### Human Readable Output

>### Watchlists
>
>|Watchlist ID|Watchlist Name|Watchlist Type|Watchlist Sub Type|
>|---|---|---|---|
>| 1 | Attack Vendor | TOPIC | CYBER |
>| 2 | Cyber-Physical | TOPIC | VULNERABILITY |

### dataminrpulse-alerts-get

***
Retrieves the alerts as per the provided watchlist_ids or query or configured watchlist_names parameter in integration.

Note: The "from" and "to" arguments should not be included on the first execution, there will not be any "from" or "to" cursor to reference. Only subsequent calls should contain those parameters.

#### Base Command

`dataminrpulse-alerts-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_ids | Comma-separated set of watchlist IDs. | Optional |
| query | Terms to search within Dataminr Alerts. | Optional |
| from | It points to a cursor that you want any alerts after. Note that only one of "from" or "to" can be included per request. | Optional |
| to | It points to a cursor that you want any alerts before. Note that only one of "from" and "to" can be included per request. | Optional |
| num | Maximum number of alerts to return. 100 is maximum value. Default is 40. | Optional |
| use_configured_watchlist_names | A Boolean indicating that If user does not provide watchlist IDs then it should use configured watchlist names with query parameter. Possible values are: yes, no. Default is yes. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DataminrPulse.Alerts.alertId | String | The unique identifier of the alert. |
| DataminrPulse.Alerts.alertTimestamp | String | The timestamp when the alert was generated. |
| DataminrPulse.Alerts.alertType.name | String | The type of alert. |
| DataminrPulse.Alerts.alertTopics.id | String | The topic ID associated with the alert. |
| DataminrPulse.Alerts.alertTopics.name | String | The topic name associated with the alert. |
| DataminrPulse.Alerts.alertCompanies.name | String | The company name is related to the alert. |
| DataminrPulse.Alerts.alertCompanies.ticker | String | The stock ticker symbol of the company. |
| DataminrPulse.Alerts.alertSectors.name | String | The sector name associated with the alert. |
| DataminrPulse.Alerts.headline | String | The main headline or summary of the alert. |
| DataminrPulse.Alerts.subHeadline.title | String | The subheadline title. |
| DataminrPulse.Alerts.subHeadline.content | String | The subheadline detailed content. |
| DataminrPulse.Alerts.publicPost.timestamp | String | The timestamp of the original public post. |
| DataminrPulse.Alerts.publicPost.href | String | The source URL of the public post. |
| DataminrPulse.Alerts.publicPost.text | String | The text of the public post. |
| DataminrPulse.Alerts.publicPost.channels | String | The channels or platforms where the post appeared. |
| DataminrPulse.Alerts.publicPost.media.type | String | The type of attached media. |
| DataminrPulse.Alerts.publicPost.media.href | String | The media hyperlink. |
| DataminrPulse.Alerts.publicPost.englishText | String | The english text of the public post. |
| DataminrPulse.Alerts.eventCorroboration.timestamp | String | The timestamp of the event corroboration. |
| DataminrPulse.Alerts.eventCorroboration.summary.title | String | The title of the event corroboration summary. |
| DataminrPulse.Alerts.eventCorroboration.summary.content | String | The content of the event corroboration summary. |
| DataminrPulse.Alerts.estimatedEventLocation.name | String | The estimated name or location of the event. |
| DataminrPulse.Alerts.estimatedEventLocation.coordinates | Number | The coordinates of the estimated event location. |
| DataminrPulse.Alerts.estimatedEventLocation.probabilityRadius | Number | The probability radius of the estimated location. |
| DataminrPulse.Alerts.assetsMatched.locationAssets.name | String | The name of the customer location asset. |
| DataminrPulse.Alerts.assetsMatched.locationAssets.lng | Number | The longitude of the asset. |
| DataminrPulse.Alerts.assetsMatched.locationAssets.lat | Number | The latitude of the asset. |
| DataminrPulse.Alerts.assetsMatched.locationAssets.distanceFromEventLocation | Number | The distance between the asset and the alert's estimated event location. |
| DataminrPulse.Alerts.assetsMatched.locationAssets.locationGroups.name | String | The name of the location group. |
| DataminrPulse.Alerts.assetsMatched.thirdPartyAssets.name | String | The name of the third-party asset. |
| DataminrPulse.Alerts.assetsMatched.thirdPartyAssets.customerProvidedId | String | The customer-provided unique ID for the asset. |
| DataminrPulse.Alerts.assetsMatched.travelSegments.name | String | The name of the travel segment location or asset. |
| DataminrPulse.Alerts.assetsMatched.travelSegments.lng | Number | The longitude of the asset. |
| DataminrPulse.Alerts.assetsMatched.travelSegments.lat | Number | The latitude of the asset. |
| DataminrPulse.Alerts.assetsMatched.travelSegments.distanceFromEventLocation | Number | The distance between the asset and the alert's estimated event location. |
| DataminrPulse.Alerts.assetsMatched.travelSegments.travelType | String | The category of travel segment, such as HOTEL or FLIGHT. |
| DataminrPulse.Alerts.intelAgents.summary.type | String | The type of the intelligence agent summary. |
| DataminrPulse.Alerts.intelAgents.summary.title | String | The title of the intelligence agent summary. |
| DataminrPulse.Alerts.intelAgents.summary.content | String | The content of the intelligence agent summary. |
| DataminrPulse.Alerts.intelAgents.version | String | The version of the intelligence agent. |
| DataminrPulse.Alerts.intelAgents.timestamp | String | The timestamp of the intelligence agent. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.name | String | The name of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.type | String | The type of discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.summary | String | The summary of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.publishedDate | String | The published date of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.products.productName | String | The product name of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.products.productVendor | String | The product vendor of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.products.productVersion | String | The product version of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.knownExploitedDate | String | The known exploited date of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.epssScore | String | The EPSS score of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.cvss | String | The CVSS score of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.exploitable | String | The exploitability of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.exploitPocLinks | String | The exploit proof of concept links of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.affectedOperatingSystems | String | The affected operating systems of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.yaraRules | String | The YARA rules of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.aliases | String | The aliases of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.ttps.topLevelTechniqueName | String | The top-level technique name of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.ttps.techniqueName | String | The technique name of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.ttps.techniqueId | String | The technique ID of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.ttps.tacticName | String | The tactic name of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.countryOfOrigin | String | The country of origin of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.threatActors | String | The threat actors related to malware of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.websiteUrl | String | The website URL associated with the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.locations.address | String | The address of the location associated with the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.industry | String | The industry in which the discovered entity operates. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.primaryLocation.address | String | The primary address of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.organizationType | String | The type of organization associated with the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.headOfOrganization | String | The individual who heads the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.executives | String | The executives associated with the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.operatingRegions | String | The regions in which the discovered entity operates. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.address | String | The address information of the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.ownedBy | String | The entity or individual that owns the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.operatedBy | String | The entity or individual that operates the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.country | String | The country in which the discovered entity is located. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.timezone.utcOffsetSeconds | Number | The UTC offset in seconds for the entity's timezone. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.timezone.displayName | String | The display name of the entity's timezone. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.stateOrProvince | String | The state or province where the discovered entity is located. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.population | String | The population associated with the discovered entity's location. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.travelAdvisories.issuingCountry | String | The country issuing the travel advisory. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.travelAdvisories.issuedDate | String | The date when the travel advisory was issued. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.travelAdvisories.issuedCountry | String | The country for which the travel advisory was issued. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.travelAdvisories.advisoryText | String | The text content of the travel advisory. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.president | String | The president associated with the discovered entity's country or organization. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.officialLanguages | String | The official languages spoken in the entity's location. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.capital | String | The capital city associated with the discovered entity's country. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.locationType | String | The type of location represented by the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.managedBy | String | The entity or individual responsible for managing the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.nationalities | String | The nationalities associated with the discovered entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.pastRoles.tenureStartDate | String | The start date of the entity's past role. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.pastRoles.tenureEndDate | String | The end date of the entity's past role. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.pastRoles.roleName | String | The name of the past role associated with the entity. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.currentRoles.tenureStartDate | String | The start date of the entity's current role. |
| DataminrPulse.Alerts.intelAgents.discoveredEntities.currentRoles.roleName | String | The name of the current role associated with the entity. |
| DataminrPulse.Alerts.liveBrief.summary | String | The live brief summary. |
| DataminrPulse.Alerts.liveBrief.version | String | The live brief version. |
| DataminrPulse.Alerts.liveBrief.timestamp | String | The live brief timestamp. |
| DataminrPulse.Alerts.dataminrAlertUrl | String | The Dataminr alert detail URL. |
| DataminrPulse.Alerts.alertReferenceTerms.text | String | The reference keywords or terms for the alert. |
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.id | String | The vulnerability ID. |
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.publishedDate | String | The published date of the vulnerability. |
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.knownExploitedDate | String | The known exploited date of the vulnerability. |
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.epssScore | String | The EPSS score of the vulnerability. |
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.cvss | Number | The CVSS score of the vulnerability. |
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.products.productName | String | The vulnerable product name. |
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.products.productVendor | String | The vulnerable product vendor. |
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.products.productVersion | String | The vulnerable product version. |
| DataminrPulse.Alerts.metadata.cyber.vulnerabilities.exploitPocLinks | String | The exploit PoC links for the vulnerability. |
| DataminrPulse.Alerts.metadata.cyber.URL.name | String | The related URL name. |
| DataminrPulse.Alerts.metadata.cyber.addresses.ip | String | The IP address involved. |
| DataminrPulse.Alerts.metadata.cyber.addresses.port | Number | The port number involved. |
| DataminrPulse.Alerts.metadata.cyber.addresses.version | String | The protocol or software version of the address. |
| DataminrPulse.Alerts.metadata.cyber.addresses.type | String | The type of the address. |
| DataminrPulse.Alerts.metadata.cyber.malware.name | String | The malware name. |
| DataminrPulse.Alerts.metadata.cyber.malware.affectedOperatingSystems | String | The affected operating systems. |
| DataminrPulse.Alerts.metadata.cyber.threatActors.name | String | The threat actor name. |
| DataminrPulse.Alerts.metadata.cyber.threatActors.aliases | String | The threat actor aliases. |
| DataminrPulse.Alerts.metadata.cyber.threatActors.countriesOfOrigin | String | The countries of origin of the threat actor. |
| DataminrPulse.Alerts.metadata.cyber.asOrgs.asn | String | The autonomous system number. |
| DataminrPulse.Alerts.metadata.cyber.asOrgs.asOrg | String | The autonomous system organization. |
| DataminrPulse.Alerts.metadata.cyber.hashValues.value | String | The hash value. |
| DataminrPulse.Alerts.metadata.cyber.hashValues.type | String | The hash type. |
| DataminrPulse.Alerts.listsMatched.id | String | The matched list ID. |
| DataminrPulse.Alerts.listsMatched.name | String | The matched list name. |
| DataminrPulse.Alerts.listsMatched.subType | String | The subtype of the matched list. |
| DataminrPulse.Alerts.listsMatched.topicIds | String | The topic IDs of the matched list. |
| DataminrPulse.Alerts.linkedAlerts.count | Number | The count of linked alerts. |
| DataminrPulse.Alerts.linkedAlerts.parentAlertId | String | The parent alert ID of the linked alert. |
| DataminrPulse.Cursor.from | String | The "from" points to a cursor that specifies the alerts you want after it. |
| DataminrPulse.Cursor.to | String | The "to" points to a cursor that specifies the alerts you want before it. |

#### Command example

```!dataminrpulse-alerts-get num=1```

#### Context Example

```json
{
    "DataminrPulse": {
        "Alerts": [
            {
                "alertId": "DUMMY_ALERT_ID",
                "alertTimestamp": "2025-07-07T19:19:00.397Z",
                "alertType": {
                    "name": "Alert"
                },
                "alertTopics": [
                    {
                        "id": "DUMMY_TOPIC_ID",
                        "name": "DUMMY_TOPIC_NAME"
                    }
                ],
                "alertCompanies": [
                    {
                        "name": "DUMMY_COMPANY",
                        "ticker": "DUMMY_TICKER"
                    }
                ],
                "alertSectors": [
                    {
                        "name": "DUMMY_SECTOR"
                    }
                ],
                "headline": "Spike detected in discussion related to threat actor DUMMY_ACTOR.",
                "subHeadline": {
                    "title": "DUMMY_TITLE",
                    "content": [
                        "DUMMY_CONTENT"
                    ]
                },
                "publicPost": {
                    "timestamp": "2025-01-01T00:00:00.000Z",
                    "href": "DUMMY_URL",
                    "channels": [
                        "DUMMY_CHANNEL"
                    ],
                    "media": [
                        {
                            "type": "photo",
                            "href": "DUMMY_IMAGE_URL"
                        }
                    ]
                },
                "estimatedEventLocation": {
                    "name": "DUMMY_LOCATION",
                    "coordinates": [
                        0,
                        0
                    ],
                    "probabilityRadius": 0
                },
                "intelAgents": [
                    {
                        "summary": [
                            {
                                "type": [
                                    "CYBER"
                                ],
                                "title": "Background Information",
                                "content": [
                                    "This is a placeholder description for background information related to the issue."
                                ]
                            },
                            {
                                "type": [
                                    "CYBER"
                                ],
                                "title": "Current Status",
                                "content": [
                                    "This is a placeholder description for the current status of the issue."
                                ]
                            },
                            {
                                "type": [
                                    "CYBER"
                                ],
                                "title": "Impact",
                                "content": [
                                    "This is a placeholder description for the potential impact of the issue."
                                ]
                            }
                        ],
                        "version": "prior",
                        "timestamp": "2025-01-01T00:00:00.000Z",
                        "discoveredEntities": [
                            {
                                "name": "DUMMY_ENTITY",
                                "type": "threatActor",
                                "aliases": [
                                    "DUMMY_ALIAS"
                                ]
                            },
                            {
                                "name": "DUMMY_ENTITY02",
                                "type": "malware",
                                "affectedOperatingSystems": [
                                    "DUMMY_OS"
                                ]
                            },
                            {
                                "name": "DUMMY_ENTITY03",
                                "type": "vulnerability",
                                "publishedDate": "2025-01-01T00:00:00.000Z",
                                "epssScore": 2.0,
                                "cvss": 2.5,
                                "products": [
                                    {
                                        "productName": "DUMMY_PRODUCT",
                                        "productVendor": "DUMMY_VENDOR",
                                        "productVersion": "DUMMY_VERSION"
                                    }
                                ],
                                "exploitPocLinks": [
                                    "DUMMY_LINK"
                                ]
                            }
                        ]
                    }
                ],
                "liveBrief": [
                    {
                        "summary": "DUMMY_LIVEBRIEF",
                        "version": "prior",
                        "timestamp": "2025-01-01T00:00:00.000Z"
                    }
                ],
                "dataminrAlertUrl": "https://app.dataminr.com/#alertDetail/DUMMY",
                "alertReferenceTerms": [
                    {
                        "text": "DUMMY_REF_TERM"
                    }
                ],
                "metadata": {
                    "cyber": {
                        "vulnerabilities": [
                            {
                                "id": "DUMMY_VULN",
                                "publishedDate": "2025-01-01T00:00:00.000Z",
                                "epssScore": 2.0,
                                "cvss": 2.5,
                                "products": [
                                    {
                                        "productName": "DUMMY_PRODUCT",
                                        "productVendor": "DUMMY_VENDOR",
                                        "productVersion": "DUMMY_VERSION"
                                    }
                                ],
                                "exploitPocLinks": [
                                    "DUMMY_LINK"
                                ]
                            }
                        ],
                        "URL": [
                            {
                                "name": "DUMMY_URL"
                            }
                        ],
                        "addresses": [
                            {
                                "ip": "0.0.0.0",
                                "port": 22,
                                "version": "DUMMY_VERSION"
                            }
                        ],
                        "malware": [
                            {
                                "name": "DUMMY_MALWARE"
                            }
                        ],
                        "threatActors": [
                            {
                                "name": "DUMMY_ACTOR"
                            }
                        ],
                        "asOrgs": [
                            {
                                "asn": "DUMMY_ASN",
                                "asOrg": "DUMMY_ORG"
                            }
                        ],
                        "hashValues": [
                            {
                                "value": "DUMMY_HASH",
                                "type": "DUMMY_HASH_TYPE"
                            }
                        ]
                    }
                },
                "listsMatched": [
                    {
                        "id": 3,
                        "name": "Data Security",
                        "subType": "CYBER",
                        "topicIds": [
                            "DUMMY_TOPIC_ID"
                        ]
                    }
                ],
                "linkedAlerts": [
                    {
                        "count": 4,
                        "parentAlertId": "DUMMY_PARENT_ID"
                    }
                ]
            }
        ],
        "Cursor": {
            "from": "DUMMY_CURSOR02",
            "to": "DUMMY_CURSOR01"
        }
    }
}
```

#### Human Readable Output

>### Alerts
>
>|Alert Type|Alert ID|Alert Name|Intel Agents Summary|Intel Agents Discovered Entities|Live Brief|Watchlist Name|Alert Time|Alert Location|Post Link|Alert Topics|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Alert | [DUMMY_ALERT_ID](https://app.dataminr.com/#alertDetail/DUMMY) | Spike detected in discussion related to threat actor DUMMY_ACTOR. | **-** ***type***: CYBER<br> ***title***: Background Information<br> ***content***: This is a placeholder description for background information related to the issue.<br>**-** ***type***: CYBER<br> ***title***: Current Status<br> ***content***: This is a placeholder description for the current status of the issue.<br>**-** ***type***: CYBER<br> ***title***: Impact<br> ***content***: This is a placeholder description for the potential impact of the issue. | **-** ***name***: DUMMY_ENTITY<br> ***type***: threatActor<br> ***aliases***: DUMMY_ALIAS<br>**-** ***name***: DUMMY_ENTITY02<br> ***type***: malware<br> ***affectedOperatingSystems***: DUMMY_OS<br>**-** ***name***: DUMMY_ENTITY03<br> ***type***: vulnerability<br> ***publishedDate***: 2025-01-01T00:00:00.000Z<br> ***epssScore***: 2.0<br> ***cvss***: 2.5<br> **products**:<br>  **-** ***productName***: DUMMY_PRODUCT<br>   ***productVendor***: DUMMY_VENDOR<br>   ***productVersion***: DUMMY_VERSION<br> ***exploitPocLinks***: DUMMY_LINK | **-** ***summary***: DUMMY_LIVEBRIEF<br> ***version***: prior<br> ***timestamp***: 2025-01-01T00:00:00.000Z | Data Security | 2025-07-07T19:19:00.397Z | DUMMY_LOCATION | [DUMMY_URL](http://dummy.com) | **-** ***id***: DUMMY_TOPIC_ID<br> ***name***: DUMMY_TOPIC_NAME |

>### Cursor for pagination
>
>|from|to|
>|---|---|
>| DUMMY_CURSOR02 | DUMMY_CURSOR01 |

## Migration Guide

### Migrated Commands

Below is the list of commands that have been migrated from the "Dataminr Pulse" integration to the "Dataminr Pulse - ReGenAI" integration.

- dataminrpulse-alerts-get
- dataminrpulse-watchlists-get

### Deprecated Commands

The following command from the previous integration has been deprecated from the Dataminr Pulse API side with no replacement.

- dataminrpulse-related-alerts-get
