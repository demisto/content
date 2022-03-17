Accenture CTI provides intelligence regarding security threats and vulnerabilities.
This integration was integrated and tested with version v2.90.0 of ACTI
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
| uuid | UUID to fetch Intelligence Alerts & Intelligence Reports. | Yes | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAIR.abstract | String | This field is specific to Intelligence Alert and provides a summarised context, for example, 'The worldwide COVID-19 outbreak...' |   
| IAIR.last_published | String | The last published timestamp of the IA/IR, for example, '2020-06-26T01:14:56.000Z' |
| IAIR.index_timestamp | String | The index timestamp of the IA/IR, for example, '2022-02-11T17:24:03.604Z' |
| IAIR.display_text | String | The display text of the IA/IR, for example, 'SITREP Cybersecurity Risks Related to COVID-19' |
| IAIR.value | String | The value of the IA/IR, for example, 'https://intelgraph.idefense.com/#/node/intelligence_alert/view/8b8b48f1-92a0-411a-a073-3241f6819f8b' |
| IAIR.last_modified | String | The last modified timestamp of the IA/IR, for example, '2022-02-11T17:21:48.000Z' |
| IAIR.threat_types | String | The threat type of the IA/IR, for example, '- Hacktivism- Cyber Espionage- Cyber Crime- Vulnerability'. It's formatted in such a way that it gets displayed better. |
| IAIR.created_on | String | The creation timestamp of the IA/IR, for example, '2020-03-12T22:22:25.000Z' |
| IAIR.title | String | The title of the IA/IR, for example, 'SITREP Cybersecurity Risks Related to COVID-19' |
| IAIR.type | String | The type of report i.e. an IA/IR , for example, 'intelligence_alert' |
| IAIR.uuid | String | The uuid of the IA/IR, for example, '8b8b48f1-92a0-411a-a073-3241f6819f8b' |
| IAIR.analysis | String | The analysis of the IA/IR, for example, 'COVID-19 Introduces Cyberthreat Opportunities...' |
| IAIR.attachment_links | String | Provides with the document links related to the Intelligence Alert. This field is specific to Intelligence Alert, for example, 'https://intelgraph.idefense.com/rest/files/download/...' |
| IAIR.severity | String | Provides severity rating. This field is specific to Intelligence Alert, for example, '4' |
| IAIR.mitigation | String | Provides info on how to mitigate. This field is specific to Intelligence Alert, for example, '## Expert, Experienced Advice Will be CriticalTo minimize targeting opportunities...' |
| IAIR.conclusion | String | Provides conclusion of the report. This field is specific to Intelligence Report. |
| IAIR.summary | String | Provides with a summary of the report. This field is specific to Intelligence Report. |
| IAIR.dynamic_properties | String | Provides with the dynamic properties related to the intelligence alert/report. |
| IAIR.links | String | Provides details of the linked fields related to the intelligence alert/report. |
| IAIR.sources_external | String | Provides with external sources related to the intelligence alert/report. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor that was used to calculate the score. |
| DBotScore.Score | String | The actual score. |


#### Command Example
```!acti-getThreatIntelReport uuid=8b8b48f1-92a0-411a-a073-3241f6819f8b```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8b8b48f1-92a0-411a-a073-3241f6819f8b",
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
        "value": "8b8b48f1-92a0-411a-a073-3241f6819f8b",
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
        "mitigation": "##Expert, Experienced Advice Will be CriticalTo minimize targeting opportunities...."
    }
}
```

#### Human Readable Output

>Report has been fetched!
><br>UUID: 8b8b48f1-92a0-411a-a073-3241f6819f8b
><br>Link to view report: https://intelgraph.idefense.com/#/node/intelligence_alert/view/8b8b48f1-92a0-411a-a073-3241f6819f8b

