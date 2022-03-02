Accenture CTI provides intelligence regarding security threats and vulnerabilities.
This integration was integrated and tested with version v2.89.0 of ACTI
## Configure ACTI ThreatIntel Report on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ACTI ThreatIntel Report.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL | True |
| api_token | API Token | True |
| Source Reliability | Reliability of the source providing the intelligence data. | B - Usually reliable |
| insecure | Trust any certificate \(not secure\) | False |
| use_proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### acti-getThreatIntelReport
***
Fetches intelligence alerts and reports from ACTI IntelGraph to XSOAR platform.


#### Base Command

`acti-getThreatIntelReport`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to fetches Intelligence Alerts & Intelligence Reports. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAIR.abstract | String | The abstract of the IAIR, for example: The worldwide COVID-19 outbreak... |   
| IAIR.last_published | String | The last published date of the IAIR, for example: 2020-06-26T01:14:56.000Z |
| IAIR.index_timestamp | String | The index timestamp of the IAIR, for example: 2022-02-11T17:24:03.604Z |
| IAIR.display_text | String | The display text of the IAIR, for example: SITREP: Cybersecurity Risks Related to COVID-19 |
| IAIR.value | String | The value of the IAIR, for example: https://intelgraph.idefense.com/#/node/intelligence_alert/view/8b8b48f1-92a0-411a-a073-3241f6819f8b |
| IAIR.last_modified | String | The last modified date of the IAIR, for example: 2022-02-11T17:21:48.000Z |
| IAIR.threat_types | String | The threat type of the IAIR, for example: - Hacktivism- Cyber Espionage- Cyber Crime- Vulnerability |
| IAIR.created_on | String | The created date of the IAIR, for example: 2020-03-12T22:22:25.000Z |
| IAIR.title | String | The title of the IAIR, for example: SITREP: Cybersecurity Risks Related to COVID-19 |
| IAIR.type | String | The type of the IAIR, for example: intelligence_alert |
| IAIR.uuid | String | The uuid of the IAIR, for example: 8b8b48f1-92a0-411a-a073-3241f6819f8b |
| IAIR.analysis | String | The analysis of the IAIR, for example: COVID-19 Introduces Cyberthreat Opportunities |
| IAIR.attachment_links | String | The attachment links of the IAIR, for example:  https://intelgraph.idefense.com/rest/files/download/....... |
| IAIR.severity | String | The severity of the IAIR, for example: 4 |
| IAIR.key | String | The key of the IAIR, for example: c0ea8f2f-372c-44d1-ad81-efde4971110e |
| IAIR.mitigation | String | The mitigation of the IAIR, for example: ##Expert, Experienced Advice Will be CriticalTo minimize targeting opportunities.... |



#### Command Example
```!acti-getThreatIntelReport url=https://intelgraph.idefense.com/#/node/intelligence_alert/view/8b8b48f1-92a0-411a-a073-3241f6819f8b```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "https://intelgraph.idefense.com/#/node/intelligence_alert/view/8b8b48f1-92a0-411a-a073-3241f6819f8b",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "ACTI Intelligence Alert",
        "Vendor": "ACTI Threat Intelligence Report"
    },
    "IAIR": {
        "abstract": "The worldwide COVID-19 outbreak, which the World Health Organization (WHO) declared a pandemic......",
        "last_published": "2020-06-26T01:14:56.000Z",
        "index_timestamp": "2022-02-11T17:24:03.604Z",
        "display_text": "SITREP: Cybersecurity Risks Related to COVID-19",
        "value": "https://intelgraph.idefense.com/#/node/intelligence_alert/view/8b8b48f1-92a0-411a-a073-3241f6819f8b",
        "sources_external": {},
        "last_modified":"2022-02-11T17:21:48.000Z",
        "dynamic_properties": {},
        "threat_types": "- Hacktivism- Cyber Espionage- Cyber Crime- Vulnerability",
        "created_on": "2020-03-12T22:22:25.000Z",
        "title": "SITREP: Cybersecurity Risks Related to COVID-19",
        "links":{},
        "type": "intelligence_alert",
        "uuid": "8b8b48f1-92a0-411a-a073-3241f6819f8b",
        "analysis": "##COVID-19 Introduces Cyberthreat Opportunities####Exploitation of Work-from-Home.....",
        "attachment_links": "- https://intelgraph.idefense.com/rest/files/download/08/f0/05/7f1f609e7659dc......",
        "severity": 4,
        "key":"c0ea8f2f-372c-44d1-ad81-efde4971110e",
        "mitigation": "##Expert, Experienced Advice Will be CriticalTo minimize targeting opportunities...."
    }
}
```

#### Human Readable Output

>### Results
>Report has been fetched!
>UUID: 8b8b48f1-92a0-411a-a073-3241f6819f8b
>URL to view report:https://intelgraph.idefense.com/#/node/intelligence_alert/view/8b8b48f1-92a0-411a-a073-3241f6819f8b

