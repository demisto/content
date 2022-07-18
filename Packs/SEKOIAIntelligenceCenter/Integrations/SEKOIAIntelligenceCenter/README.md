Fetch Indicator and Observables from SEKOIA.IO Intelligence Center.
To use this integration, please create an API Key with the right permissions.

This integration was integrated and tested with version 2022 of SEKOIAIntelligenceCenter

## Configure SEKOIAIntelligenceCenter on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SEKOIAIntelligenceCenter.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | None | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### GetObservable
***
Query SEKOIA.IO Intelligence Center for information about this observable. 


#### Base Command

`GetObservable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Indicator value. | Required | 
| type | Indicator type. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetObservable.Output | String | SEKOIA.IO returned data | 
| SEKOIAIntelligenceCenter.has_more | Boolean | Is more information available | 
| SEKOIAIntelligenceCenter.total | Number | Total number of object returned | 
| SEKOIAIntelligenceCenter.items.x_inthreat_short_display | String | Short display name of the observable | 
| SEKOIAIntelligenceCenter.items.modified | Date | Modification date of the observable | 
| SEKOIAIntelligenceCenter.items.spec_version | String | STIX specification version | 
| SEKOIAIntelligenceCenter.items.created | Date | Observable creation date | 
| SEKOIAIntelligenceCenter.items.type | String | Observable type | 
| SEKOIAIntelligenceCenter.items.x_inthreat_sources_refs | String | Unique identifier of the observable source | 
| SEKOIAIntelligenceCenter.items.value | String | Value of the item | 
| SEKOIAIntelligenceCenter.items.id | String | Unique identifier of the item | 

#### Command example
```!GetObservable value="eicar@sekoia.io" type="email-addr"```
#### Context Example
```json
{
    "SEKOIAIO": {
        "Observable": {
            "indicator": {
                "type": "email-addr",
                "value": "eicar@sekoia.io"
            },
            "items": [
                {
                    "created": "2020-11-04T00:27:15.9801Z",
                    "id": "email-addr--cd6440d1-725c-5eb9-bff0-5e62c65ee263",
                    "modified": "2020-11-04T00:27:15.9801Z",
                    "spec_version": "2.1",
                    "type": "email-addr",
                    "value": "eicar@sekoia.io",
                    "x_inthreat_short_display": "eicar@sekoia.io",
                    "x_inthreat_sources_refs": [
                        "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                    ],
                    "x_inthreat_tags": []
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Observable eicar@sekoia.io
>|modified|created|
>|---|---|
>| 2020-11-04T00:27:15.9801Z | 2020-11-04T00:27:15.9801Z |
>### Associated tags
>**No entries.**
>Please consult the [dedicated page](https:<span>//</span>app.sekoia.io/intelligence/objects/email-addr--cd6440d1-725c-5eb9-bff0-5e62c65ee263) for more information.


### GetIndicator
***
Query SEKOIA.IO Intelligence Center for information about this indicator. No information is returned if the value is not a known by SEKOIA.IO as an indicator (IoC).


#### Base Command

`GetIndicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Indicator value. | Required | 
| type | Indicator type. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SEKOIAIntelligenceCenter.has_more | Boolean | Is more information available | 
| SEKOIAIntelligenceCenter.items.lang | String | Language of the indicator data | 
| SEKOIAIntelligenceCenter.items.x_ic_is_in_flint | Boolean | Is this indicator from a SEKOIA FLINT report | 
| SEKOIAIntelligenceCenter.items.kill_chain_phases.kill_chain_name | String | Name of the kill chain used | 
| SEKOIAIntelligenceCenter.items.kill_chain_phases.phase_name | String | Name of the kill chain phase | 
| SEKOIAIntelligenceCenter.items.name | String | Name of the item | 
| SEKOIAIntelligenceCenter.items.valid_until | Date | Expiration date of the item | 
| SEKOIAIntelligenceCenter.items.x_ic_deprecated | Boolean | Is the item deprecated | 
| SEKOIAIntelligenceCenter.items.x_inthreat_sources_refs | String | Source references of the observable | 
| SEKOIAIntelligenceCenter.items.spec_version | String | STIX specification version used | 
| SEKOIAIntelligenceCenter.items.description | String | Item description | 
| SEKOIAIntelligenceCenter.items.modified | Date | Last modification date of the item | 
| SEKOIAIntelligenceCenter.items.id | String | Unique identifier of the item | 
| SEKOIAIntelligenceCenter.items.created_by_ref | String | Unique identifier of the creator of the item | 
| SEKOIAIntelligenceCenter.items.pattern | String | STIX pattern of the item | 
| SEKOIAIntelligenceCenter.items.pattern_type | String | STIX pattern type | 
| SEKOIAIntelligenceCenter.items.valid_from | Date | Beginning of the item validity date | 
| SEKOIAIntelligenceCenter.items.x_ic_observable_types | String | Intelligence Center observable types | 
| SEKOIAIntelligenceCenter.items.type | String | STIX Object type | 
| SEKOIAIntelligenceCenter.items.revoked | Boolean | Is this item revoked | 
| SEKOIAIntelligenceCenter.items.object_marking_refs | String | Unique identifier of the marking reference \(TLP\) | 
| SEKOIAIntelligenceCenter.items.created | Date | Creation date of the item | 
| SEKOIAIntelligenceCenter.items.indicator_types | String | STIX indicator types | 

#### Command example
```!GetIndicator value="eicar@sekoia.io" type="email-addr"```
#### Context Example
```json
{
    "SEKOIAIntelligenceCenter": {
        "Analysis": {
            "indicator": {
                "type": "email-addr",
                "value": "eicar@sekoia.io"
            },
            "items": [
                {
                    "created": "2020-05-25T07:18:29.384153Z",
                    "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                    "description": "SEKOIA EICAR unit is known to have used in the past this email address to distribute EICAR dropper during phishing campaign.\n",
                    "id": "indicator--d394449b-6bc7-4d48-b392-6f898190bd2a",
                    "indicator_types": [
                        "benign"
                    ],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                            "phase_name": "delivery"
                        }
                    ],
                    "lang": "en",
                    "modified": "2020-06-02T13:29:24.940899Z",
                    "name": "eicar@sekoia.io",
                    "object_marking_refs": [
                        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                    ],
                    "pattern": "[email-addr:value = 'eicar@sekoia.io']",
                    "pattern_type": "stix",
                    "revoked": false,
                    "spec_version": "2.1",
                    "type": "indicator",
                    "valid_from": "2020-05-25T07:18:01.809Z",
                    "valid_until": "2022-11-20T23:00:00.000Z",
                    "x_ic_deprecated": false,
                    "x_ic_is_in_flint": false,
                    "x_ic_observable_types": [
                        "email-addr"
                    ],
                    "x_inthreat_sources_refs": [
                        "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Indicator eicar@sekoia.io is categorized as ['benign']
>
>SEKOIA EICAR unit is known to have used in the past this email address to distribute EICAR dropper during phishing campaign.
>### Kill chain
>|kill_chain_name|phase_name|
>|---|---|
>| lockheed-martin-cyber-kill-chain | delivery |
>
>
>Please consult the [dedicated page](https:<span>//</span>app.sekoia.io/intelligence/objects/indicator--d394449b-6bc7-4d48-b392-6f898190bd2a) for more information.


### GetIndicatorContext
***
Query SEKOIA.IO Intelligence Center for context around this indicator


#### Base Command

`GetIndicatorContext`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Indicator value. | Required | 
| type | Indicator type. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SEKOIAIntelligenceCenter.items.type | String | Observable type | 
| SEKOIAIntelligenceCenter.items.id | String | Unique identifier of the item | 
| SEKOIAIntelligenceCenter.items.objects.valid_from | Date | Beginning of the item validity date | 
| SEKOIAIntelligenceCenter.items.objects.x_inthreat_sources_refs | String | Unique identifier of the observable source | 
| SEKOIAIntelligenceCenter.items.objects.spec_version | String | STIX specification version | 
| SEKOIAIntelligenceCenter.items.objects.x_ic_is_in_flint | Boolean | Is this indicator from a SEKOIA FLINT report | 
| SEKOIAIntelligenceCenter.items.objects.lang | String | Language of the indicator data | 
| SEKOIAIntelligenceCenter.items.objects.x_ic_impacted_locations | String | UUID of the impacted locations | 
| SEKOIAIntelligenceCenter.items.objects.id | String | UUID of the objects | 
| SEKOIAIntelligenceCenter.items.objects.created_by_ref | String | Unique identifier of the creator of the item | 
| SEKOIAIntelligenceCenter.items.objects.modified | Date | Modification date of the observable | 
| SEKOIAIntelligenceCenter.items.objects.type | String | STIX Object type | 
| SEKOIAIntelligenceCenter.items.objects.revoked | Boolean | Is this item revoked | 
| SEKOIAIntelligenceCenter.items.objects.created | Date | Creation date of the item | 
| SEKOIAIntelligenceCenter.items.objects.x_ic_observable_types | String | Intelligence Center observable types | 
| SEKOIAIntelligenceCenter.items.objects.pattern_type | String | STIX pattern type | 
| SEKOIAIntelligenceCenter.items.objects.name | String | Name of the item | 
| SEKOIAIntelligenceCenter.items.objects.pattern | String | STIX pattern | 
| SEKOIAIntelligenceCenter.items.objects.indicator_types | String | STIX indicator types | 
| SEKOIAIntelligenceCenter.items.objects.object_marking_refs | String | Unique identifier of the Object Marking reference \(TLP\) | 
| SEKOIAIntelligenceCenter.items.objects.x_ic_impacted_sectors | String | UUID of the impacted sectors | 
| SEKOIAIntelligenceCenter.items.objects.kill_chain_phases.kill_chain_name | String | Name of the kill chain used | 
| SEKOIAIntelligenceCenter.items.objects.kill_chain_phases.phase_name | String | Name of the kill chain phase | 
| SEKOIAIntelligenceCenter.items.objects.confidence | Number | Indicator confidence score | 
| SEKOIAIntelligenceCenter.items.objects.x_ic_deprecated | Boolean | Is the item deprecated | 
| SEKOIAIntelligenceCenter.items.objects.valid_until | Date | Expiration date of the item | 
| SEKOIAIntelligenceCenter.items.objects.x_ic_external_refs | String | External references | 
| SEKOIAIntelligenceCenter.items.objects.first_seen | Date | Item first seen date | 
| SEKOIAIntelligenceCenter.items.objects.aliases | String | Item aliases names | 
| SEKOIAIntelligenceCenter.items.objects.is_family | Boolean | Is the item part of a family | 
| SEKOIAIntelligenceCenter.items.objects.external_references.description | String | Object external references description | 
| SEKOIAIntelligenceCenter.items.objects.external_references.source_name | String | Object external references source name | 
| SEKOIAIntelligenceCenter.items.objects.external_references.url | String | Object external references URL | 
| SEKOIAIntelligenceCenter.items.objects.capabilities | String | Malware capabilities | 
| SEKOIAIntelligenceCenter.items.objects.malware_types | String | Malware type | 
| SEKOIAIntelligenceCenter.items.objects.implementation_languages | String | Malware implementation languages | 
| SEKOIAIntelligenceCenter.items.objects.description | String | Item description | 
| SEKOIAIntelligenceCenter.items.objects.stop_time | Date | Stop time date | 
| SEKOIAIntelligenceCenter.items.objects.relationship_type | String | STIX object relationship type | 
| SEKOIAIntelligenceCenter.items.objects.target_ref | String | Target reference UUID | 
| SEKOIAIntelligenceCenter.items.objects.source_ref | String | Source reference UUID | 
| SEKOIAIntelligenceCenter.items.objects.start_time | Date | Object start time | 
| SEKOIAIntelligenceCenter.items.objects.x_ic_is_sector | Boolean | Is the object a sector | 
| SEKOIAIntelligenceCenter.items.objects.contact_information | String | Object contact information | 
| SEKOIAIntelligenceCenter.items.objects.x_ic_is_source | Boolean | Is the object a source | 
| SEKOIAIntelligenceCenter.items.objects.sectors | String | Associated sectors | 
| SEKOIAIntelligenceCenter.items.objects.identity_class | String | Object identity class | 
| SEKOIAIntelligenceCenter.items.objects.definition_type | String | Object definition type | 
| SEKOIAIntelligenceCenter.items.objects.definition.tlp | String | TLP type | 
| SEKOIAIntelligenceCenter.has_more | Boolean | Is more information available | 
| IP.Address | String | IP address | 
| DBotScore.Indicator | String | The indicator name. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 

#### Command example
```!GetIndicatorContext value="eicar@sekoia.io" type="email-addr"```
#### Context Example
```json
{
    "SEKOIAIO": {
        "IndicatorContext": {
            "indicator": {
                "type": "email-addr",
                "value": "eicar@sekoia.io"
            },
            "items": [
                {
                    "id": "bundle--317bc378-8c48-40df-a3f5-4346a4d3c90e",
                    "objects": [
                        {
                            "created": "2020-05-25T07:18:29.384153Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "SEKOIA EICAR unit is known to have used in the past this email address to distribute EICAR dropper during phishing campaign.\n",
                            "id": "indicator--d394449b-6bc7-4d48-b392-6f898190bd2a",
                            "indicator_types": [
                                "benign"
                            ],
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "delivery"
                                }
                            ],
                            "lang": "en",
                            "modified": "2020-06-02T13:29:24.940899Z",
                            "name": "eicar@sekoia.io",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "pattern": "[email-addr:value = 'eicar@sekoia.io']",
                            "pattern_type": "stix",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "indicator",
                            "valid_from": "2020-05-25T07:18:01.809Z",
                            "valid_until": "2022-11-20T23:00:00.000Z",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_observable_types": [
                                "email-addr"
                            ],
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "aliases": [
                                "EICAR",
                                "TEST EICAR SEKOIA.IO",
                                "EICAR Unit of SEKOIA"
                            ],
                            "created": "2020-05-26T13:18:26.429787Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "This Intrusion Set is known to be operated by SEKOIA by its EICAR unit. This unit aims at creating fictitious environment mimicking real attackers to present how threat intelligence can help real organizations to protect themselves.\n",
                            "external_references": [
                                {
                                    "description": "",
                                    "source_name": "SEKOIA",
                                    "url": "www.sekoia.fr"
                                }
                            ],
                            "goals": [
                                "Simulation of real Threat Actor for Test purpose"
                            ],
                            "id": "intrusion-set--4d1fd514-d9a4-45f3-988a-d811df72df2f",
                            "lang": "en",
                            "modified": "2020-06-02T13:28:51.131904Z",
                            "more_info": "[More info about EICAR Unit of SEKOIA on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/intrusion-set--4d1fd514-d9a4-45f3-988a-d811df72df2f)",
                            "name": "EICAR Unit of SEKOIA",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "resource_level": "organization",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "intrusion-set",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "created": "2020-05-26T13:24:33.119462Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--4b0306ef-f021-48b4-81e1-8de6c2cf1179",
                            "lang": "en",
                            "modified": "2020-05-29T09:00:40.635897Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "indicates",
                            "revoked": false,
                            "source_ref": "indicator--d394449b-6bc7-4d48-b392-6f898190bd2a",
                            "spec_version": "2.1",
                            "start_time": "2020-05-25T07:18:01.809Z",
                            "stop_time": "2022-11-20T23:00:00.000Z",
                            "target_ref": "intrusion-set--4d1fd514-d9a4-45f3-988a-d811df72df2f",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "confidence": 95,
                            "contact_information": "threatintel@sekoia.fr",
                            "created": "2008-01-01T00:00:00Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "SEKOIA is a French company which applies intelligence-driven cybersecurity",
                            "external_references": [
                                {
                                    "source_name": "SEKOIA website",
                                    "url": "https://www.sekoia.fr"
                                }
                            ],
                            "id": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2019-09-30T07:54:40.149166Z",
                            "name": "SEKOIA",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "sectors": [
                                "technology"
                            ],
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": true,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true
                        },
                        {
                            "created": "2019-10-09T16:10:07.239899Z",
                            "definition": {
                                "tlp": "green"
                            },
                            "definition_type": "tlp",
                            "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                            "name": "TLP:GREEN",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "spec_version": "2.1",
                            "type": "marking-definition",
                            "x_ic_deprecated": false
                        },
                        {
                            "created": "2019-10-31T16:57:02.018068Z",
                            "definition": {
                                "tlp": "white"
                            },
                            "definition_type": "tlp",
                            "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                            "name": "TLP:WHITE",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "spec_version": "2.1",
                            "type": "marking-definition",
                            "x_ic_deprecated": false
                        }
                    ],
                    "type": "bundle"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Indicator eicar@sekoia.io is linked to the following:
>|name|description|type|aliases|goals|revoked|created|modified|more_info|
>|---|---|---|---|---|---|---|---|---|
>| EICAR Unit of SEKOIA | This Intrusion Set is known to be operated by SEKOIA by its EICAR unit. This unit aims at creating fictitious environment mimicking real attackers to present how threat intelligence can help real organizations to protect themselves.<br/> | intrusion-set | EICAR,<br/>TEST EICAR SEKOIA.IO,<br/>EICAR Unit of SEKOIA | Simulation of real Threat Actor for Test purpose | false | 2020-05-26T13:18:26.429787Z | 2020-06-02T13:28:51.131904Z | [More info about EICAR Unit of SEKOIA on SEKOIA.IO](https:<span>//</span>app.sekoia.io/intelligence/objects/intrusion-set--4d1fd514-d9a4-45f3-988a-d811df72df2f) |

