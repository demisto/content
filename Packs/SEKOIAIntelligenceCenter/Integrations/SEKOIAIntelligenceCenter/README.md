Fetch Indicator and Observables from SEKOIA.IO Intelligence Center.
To use this integration, please create an API Key with the right permissions.

This integration was integrated and tested with version 2.20220712 of SEKOIA.IO Intelligence Center.

## Configure SEKOIAIntelligenceCenter in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| None | The API Key to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. |  |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
    "SEKOIAIntelligenceCenter": {
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
>Please consult the [dedicated page](https://app.sekoia.io/intelligence/objects/email-addr--cd6440d1-725c-5eb9-bff0-5e62c65ee263) for more information.


### GetIndicator

***
Query SEKOIA.IO Intelligence Center for information about this indicator. No information is returned if the value is not a known by SEKOIA.IO as an indicator (IoC). STIX IDs can be resolved from SEKOIA.IO Intelligence Center application.


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
>Please consult the [dedicated page](https://app.sekoia.io/intelligence/objects/indicator--d394449b-6bc7-4d48-b392-6f898190bd2a) for more information.


### ip

***
Query SEKOIA.IO Intelligence Center for information about this indicator. No information is returned if the value is not a known by SEKOIA.IO as an indicator (IoC). STIX IDs can be resolved from SEKOIA.IO Intelligence Center application.


#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Indicator value. | Required | 


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
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example

```!ip ip="206.189.85.18"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "206.189.85.18",
        "Reliability": "F - Reliability cannot be judged",
        "Score": 2,
        "Type": "ip",
        "Vendor": "SEKOIAIntelligenceCenter"
    },
    "IP": {
        "Address": "206.189.85.18",
        "TrafficLightProtocol": "white"
    },
    "SEKOIAIntelligenceCenter": {
        "IP": {
            "confidence": 100,
            "created": "2021-10-01T11:22:26.759763Z",
            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
            "id": "indicator--368e5bc7-5fa2-47da-b175-2ab7222a428a",
            "indicator_types": [
                "malicious-activity"
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                    "phase_name": "command-and-control"
                },
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "command-and-control"
                }
            ],
            "lang": "en",
            "modified": "2022-11-21T10:48:30.951331Z",
            "name": "206.189.85.18",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
            "pattern": "[ipv4-addr:value = '206.189.85.18']",
            "pattern_type": "stix",
            "revoked": false,
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2021-10-01T00:00:00Z",
            "valid_until": "2022-12-01T00:00:00Z",
            "x_ic_deprecated": false,
            "x_ic_external_refs": [
                "indicator--741745ea-fae4-45fb-a66a-81cdbaacda45"
            ],
            "x_ic_impacted_locations": [
                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                "location--07888608-174b-40a3-8f61-ecfbde26cf36",
                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                "location--339d05db-907d-49a3-b699-de004149adb7",
                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                "location--092a468b-54e1-4199-9737-7268c84115bd",
                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                "location--af554517-cec1-44a8-af43-111b92b380c7",
                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                "location--2adc0f69-709c-4651-aa73-c0fd063be173",
                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                "location--c10f2499-a30d-4192-b625-8dac29801910",
                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                "location--312b214e-d9ce-4b9d-a3ed-12b49043928c",
                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                "location--079c1553-452c-4890-8341-1acecdcaf851",
                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                "location--b9c12531-454c-44a9-8317-63a975993e11",
                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                "location--a0caf772-475b-44cb-a1af-ae1debc29d87",
                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                "location--58797005-647b-4fe7-b261-33160e292a99",
                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3"
            ],
            "x_ic_impacted_sectors": [
                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6"
            ],
            "x_ic_is_in_flint": true,
            "x_ic_observable_types": [
                "ipv4-addr"
            ],
            "x_inthreat_sources_refs": [
                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                "identity--556006db-0d85-4ecb-8845-89d40ae0d40f"
            ]
        },
        "IndicatorContext": {
            "indicator": {
                "type": "ipv4-addr",
                "value": "206.189.85.18"
            },
            "items": [
                {
                    "id": "bundle--b6764d7d-7d7b-44dc-931d-7bd3fab38add",
                    "objects": [
                        {
                            "confidence": 100,
                            "created": "2021-10-01T11:22:26.759763Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "indicator--368e5bc7-5fa2-47da-b175-2ab7222a428a",
                            "indicator_types": [
                                "malicious-activity"
                            ],
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "command-and-control"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "command-and-control"
                                }
                            ],
                            "lang": "en",
                            "modified": "2022-11-21T10:48:30.951331Z",
                            "name": "206.189.85.18",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "pattern": "[ipv4-addr:value = '206.189.85.18']",
                            "pattern_type": "stix",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "indicator",
                            "valid_from": "2021-10-01T00:00:00Z",
                            "valid_until": "2022-12-01T00:00:00Z",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "indicator--741745ea-fae4-45fb-a66a-81cdbaacda45"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--07888608-174b-40a3-8f61-ecfbde26cf36",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--2adc0f69-709c-4651-aa73-c0fd063be173",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--312b214e-d9ce-4b9d-a3ed-12b49043928c",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--a0caf772-475b-44cb-a1af-ae1debc29d87",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_ic_observable_types": [
                                "ipv4-addr"
                            ],
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                                "identity--556006db-0d85-4ecb-8845-89d40ae0d40f"
                            ]
                        },
                        {
                            "aliases": [
                                "FinFisher"
                            ],
                            "capabilities": [
                                "communicates-with-c2",
                                "exfiltrates-data"
                            ],
                            "confidence": 90,
                            "created": "2019-07-19T15:25:38.820741Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "[FinFisher](https://attack.mitre.org/software/S0182) is a government-grade commercial surveillance spyware reportedly sold exclusively to government agencies for use in targeted and lawful criminal investigations. It is heavily obfuscated and uses multiple anti-analysis techniques. It has other variants including [Wingbird](https://attack.mitre.org/software/S0176). (Citation: FinFisher Citation) (Citation: Microsoft SIR Vol 21) (Citation: FireEye FinSpy Sept 2017) (Citation: Securelist BlackOasis Oct 2017) (Citation: Microsoft FinFisher March 2018)",
                            "external_references": [
                                {
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/software/S0182"
                                },
                                {
                                    "description": "(Citation: FinFisher Citation) (Citation: Microsoft SIR Vol 21) (Citation: FireEye FinSpy Sept 2017) (Citation: Securelist BlackOasis Oct 2017)",
                                    "source_name": "FinFisher"
                                },
                                {
                                    "description": "(Citation: FireEye FinSpy Sept 2017) (Citation: Securelist BlackOasis Oct 2017)",
                                    "source_name": "FinSpy"
                                },
                                {
                                    "description": "FinFisher. (n.d.). Retrieved December 20, 2017.",
                                    "source_name": "FinFisher Citation",
                                    "url": "http://www.finfisher.com/FinFisher/index.html"
                                },
                                {
                                    "description": "Anthe, C. et al. (2016, December 14). Microsoft Security Intelligence Report Volume 21. Retrieved November 27, 2017.",
                                    "source_name": "Microsoft SIR Vol 21",
                                    "url": "http://download.microsoft.com/download/E/B/0/EB0F50CC-989C-4B66-B7F6-68CD3DC90DE3/Microsoft_Security_Intelligence_Report_Volume_21_English.pdf"
                                },
                                {
                                    "description": "Jiang, G., et al. (2017, September 12). FireEye Uncovers CVE-2017-8759: Zero-Day Used in the Wild to Distribute FINSPY. Retrieved February 15, 2018.",
                                    "source_name": "FireEye FinSpy Sept 2017",
                                    "url": "https://www.fireeye.com/blog/threat-research/2017/09/zero-day-used-to-distribute-finspy.html"
                                },
                                {
                                    "description": "Kaspersky Lab's Global Research & Analysis Team. (2017, October 16). BlackOasis APT and new targeted attacks leveraging zero-day exploit. Retrieved February 15, 2018.",
                                    "source_name": "Securelist BlackOasis Oct 2017",
                                    "url": "https://securelist.com/blackoasis-apt-and-new-targeted-attacks-leveraging-zero-day-exploit/82732/"
                                },
                                {
                                    "description": "Allievi, A.,Flori, E. (2018, March 01). FinFisher exposed: A researcher\u2019s tale of defeating traps, tricks, and complex virtual machines. Retrieved July 9, 2018.",
                                    "source_name": "Microsoft FinFisher March 2018",
                                    "url": "https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/"
                                },
                                {
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/software/S0182"
                                },
                                {
                                    "description": "FinSpy: unseen findings",
                                    "source_name": "Kaspersky",
                                    "url": "https://securelist.com/finspy-unseen-findings/104322/"
                                },
                                {
                                    "external_id": "S0182",
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/software/S0182"
                                }
                            ],
                            "id": "malware--a36a2045-61dd-4462-8d5a-95d6732b74c3",
                            "is_family": true,
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "installation"
                                },
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "command-and-control"
                                },
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "actions-on-objectives"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "execution"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "command-and-control"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "collection"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "exfiltration"
                                }
                            ],
                            "labels": [
                                "malware"
                            ],
                            "lang": "en",
                            "malware_types": [
                                "spyware"
                            ],
                            "modified": "2021-11-23T09:13:59.891896Z",
                            "more_info": "[More info about FinFisher on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/malware--a36a2045-61dd-4462-8d5a-95d6732b74c3)",
                            "name": "FinFisher",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "malware",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--07888608-174b-40a3-8f61-ecfbde26cf36",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--2adc0f69-709c-4651-aa73-c0fd063be173",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--312b214e-d9ce-4b9d-a3ed-12b49043928c",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--a0caf772-475b-44cb-a1af-ae1debc29d87",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_aliases": [
                                "FinFisher",
                                "FinSpy"
                            ],
                            "x_mitre_attack_spec_version": "2.1.0",
                            "x_mitre_domains": [
                                "enterprise-attack"
                            ],
                            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "x_mitre_platforms": [
                                "Windows",
                                "Android"
                            ],
                            "x_mitre_version": "1.3"
                        },
                        {
                            "confidence": 70,
                            "created": "2021-10-01T11:22:46.839768Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Seen on port ['443']",
                            "id": "relationship--30603c6c-fa3e-4151-977b-6ed450e72eba",
                            "lang": "en",
                            "modified": "2022-11-21T10:48:30.992649Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "indicates",
                            "revoked": false,
                            "source_ref": "indicator--368e5bc7-5fa2-47da-b175-2ab7222a428a",
                            "spec_version": "2.1",
                            "start_time": "2021-10-18T00:00:00Z",
                            "stop_time": "2022-12-01T00:00:00Z",
                            "target_ref": "malware--a36a2045-61dd-4462-8d5a-95d6732b74c3",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "relationship--6772484d-9418-4c8b-9141-dd77d714ea35"
                            ],
                            "x_ic_impacted_locations": [
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--07888608-174b-40a3-8f61-ecfbde26cf36",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--2adc0f69-709c-4651-aa73-c0fd063be173",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--312b214e-d9ce-4b9d-a3ed-12b49043928c",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--a0caf772-475b-44cb-a1af-ae1debc29d87",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                                "identity--556006db-0d85-4ecb-8845-89d40ae0d40f"
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
                            "confidence": 90,
                            "created": "2020-08-25T14:20:29.977968Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "SEKOIA C2 Tracker is an innovative way to find C2 servers from APT, Cybercrime groups, malware or tools. \n\nSEKOIA keeps evolving this capacity since 2019.\n\nThis method of tracking uses characteristics from web servers responses to scan (eg: certificates or HTTP headers).\n\nSEKOIA uses web services like Onyphe, Shodan, Censys and BinaryEdge to get scan data.",
                            "external_references": [
                                {
                                    "description": "",
                                    "source_name": "2020 French Analysis",
                                    "url": "https://info.sekoia.io/analyse-infrastructures-des-attaquants-cyber"
                                },
                                {
                                    "description": "",
                                    "source_name": "2021 French Analysis",
                                    "url": "https://info.sekoia.io/fr-fr/les-infrastructures-de-command-control"
                                }
                            ],
                            "id": "identity--556006db-0d85-4ecb-8845-89d40ae0d40f",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-02-03T10:06:33.714045Z",
                            "name": "SEKOIA C2 Tracker",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "confidence": 92,
                            "created": "2017-06-01T00:00:00Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2020-04-08T14:28:56.293499Z",
                            "name": "The MITRE Corporation",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
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

>### Indicator 206.189.85.18 is linked to the following:

>|name|description|type|aliases|goals|revoked|created|modified|more_info|
>|---|---|---|---|---|---|---|---|---|
>| FinFisher | [FinFisher](https://attack.mitre.org/software/S0182) is a government-grade commercial surveillance spyware reportedly sold exclusively to government agencies for use in targeted and lawful criminal investigations. It is heavily obfuscated and uses multiple anti-analysis techniques. It has other variants including [Wingbird](https://attack.mitre.org/software/S0176). (Citation: FinFisher Citation) (Citation: Microsoft SIR Vol 21) (Citation: FireEye FinSpy Sept 2017) (Citation: Securelist BlackOasis Oct 2017) (Citation: Microsoft FinFisher March 2018) | malware | FinFisher |  | false | 2019-07-19T15:25:38.820741Z | 2021-11-23T09:13:59.891896Z | [More info about FinFisher on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/malware--a36a2045-61dd-4462-8d5a-95d6732b74c3) |


### url

***
Query SEKOIA.IO Intelligence Center for information about this indicator. No information is returned if the value is not a known by SEKOIA.IO as an indicator (IoC). STIX IDs can be resolved from SEKOIA.IO Intelligence Center application.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Indicator value. | Required | 


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
| URL.Data | String | The URL | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example

```!url url="http://truesec.pro/"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "http://truesec.pro/",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "url",
        "Vendor": "SEKOIAIntelligenceCenter"
    },
    "SEKOIAIntelligenceCenter": {
        "IndicatorContext": {
            "indicator": {
                "type": "url",
                "value": "http://truesec.pro/"
            },
            "items": [
                {
                    "id": "bundle--4838142e-6318-4dc0-86f1-d8f758548b0c",
                    "objects": [
                        {
                            "confidence": 70,
                            "created": "2022-10-06T13:54:38.493542Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "indicator--e4055cbb-0921-4282-8257-1dc8feb21fd9",
                            "indicator_types": [
                                "malicious-activity"
                            ],
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "delivery"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "initial-access"
                                }
                            ],
                            "lang": "en",
                            "modified": "2022-10-06T13:54:38.493555Z",
                            "name": "http://truesec.pro/",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "pattern": "[url:value = 'http://truesec.pro/']",
                            "pattern_type": "stix",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "indicator",
                            "valid_from": "2022-10-06T00:00:00Z",
                            "valid_until": "2023-04-04T00:00:00Z",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "indicator--fcda35a2-f982-4311-9295-de89ab0165ab"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--337e49ec-fd09-4137-b795-23ced297eb46",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--20224f11-35cc-419b-8400-7ac4a1b5fcfc",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--27b80b5d-33d3-458f-ab8d-ceef9cc67a73",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--65f56a7a-c52d-490c-bb24-7f938a9f8b3c",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--3b11929b-f582-40ef-8bf9-e164f9e98533",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--8d676ee1-2a22-488f-bdc4-ceedba0dc9fc",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9a88ee06-4fa5-4df8-87a1-bfebee73571f",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--e9d6e91b-a985-4bc7-877b-eba895611b82",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--fe17c312-6959-47e1-add0-c646a58ba9b3",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--135c841a-fa34-4458-a0a2-b5a5e4653a69",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--e750e75f-a687-44f0-892f-bb27c5d7caf2",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--09551288-c63a-4d0f-916c-4a2869f8d13f",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                                "identity--35b29d72-54a3-4568-adf8-c6a0d41e3087",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--09d3cafb-b139-46ad-a13b-0b03f4e88ed6",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--940dffc4-5d82-41fc-add0-1685a155f7c8",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--1b384f3f-d25c-4bf7-82fc-423dce5765d5",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--bf39eb1f-76f0-425a-ac92-bcbee80ad111",
                                "identity--7681454e-daac-46ee-bd4e-5904a2f1043d",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8d0115ae-e9e5-46b4-8000-ee45a1549118",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--2ce5c3b6-e96f-40e4-b180-adb96d191ea6",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_ic_observable_types": [
                                "url"
                            ],
                            "x_inthreat_sources_refs": [
                                "identity--d4e6daf6-6e06-4904-bf82-76d331ba491c"
                            ]
                        },
                        {
                            "confidence": 100,
                            "created": "2020-08-27T16:06:57.165806Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.\n\nAdversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems or to gather credentials for use of [Valid Accounts](https://attack.mitre.org/techniques/T1078). Phishing may also be conducted via third-party services, like social media platforms.",
                            "external_references": [
                                {
                                    "external_id": "T1566",
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/techniques/T1566"
                                },
                                {
                                    "external_id": "CAPEC-98",
                                    "source_name": "capec",
                                    "url": "https://capec.mitre.org/data/definitions/98.html"
                                }
                            ],
                            "id": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "initial-access"
                                },
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "delivery"
                                }
                            ],
                            "lang": "en",
                            "modified": "2022-01-28T08:06:15.568392Z",
                            "more_info": "[More info about Phishing on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e)",
                            "name": "Phishing",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "attack-pattern",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--337e49ec-fd09-4137-b795-23ced297eb46",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--97287f3b-07c2-4777-838b-d6cd00ebaccb",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--0cbb95b5-06d0-4e09-aabc-2c8e8e640135",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--d2dc6c8d-c463-4872-8d43-08ca4bad5110",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--20224f11-35cc-419b-8400-7ac4a1b5fcfc",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--27b80b5d-33d3-458f-ab8d-ceef9cc67a73",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--65f56a7a-c52d-490c-bb24-7f938a9f8b3c",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--3b11929b-f582-40ef-8bf9-e164f9e98533",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--8d676ee1-2a22-488f-bdc4-ceedba0dc9fc",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--23168672-6c82-491e-8da2-fb6c5721d04f",
                                "location--9a88ee06-4fa5-4df8-87a1-bfebee73571f",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--e9d6e91b-a985-4bc7-877b-eba895611b82",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--fe17c312-6959-47e1-add0-c646a58ba9b3",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--135c841a-fa34-4458-a0a2-b5a5e4653a69",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--e750e75f-a687-44f0-892f-bb27c5d7caf2",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--09551288-c63a-4d0f-916c-4a2869f8d13f",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                                "identity--35b29d72-54a3-4568-adf8-c6a0d41e3087",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--09d3cafb-b139-46ad-a13b-0b03f4e88ed6",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--940dffc4-5d82-41fc-add0-1685a155f7c8",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--1b384f3f-d25c-4bf7-82fc-423dce5765d5",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                                "identity--58737928-ee88-432d-8ad2-ad43edec4069",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--bf39eb1f-76f0-425a-ac92-bcbee80ad111",
                                "identity--7681454e-daac-46ee-bd4e-5904a2f1043d",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8d0115ae-e9e5-46b4-8000-ee45a1549118",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--2ce5c3b6-e96f-40e4-b180-adb96d191ea6",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_data_sources": [
                                "File monitoring",
                                "Packet capture",
                                "Web proxy",
                                "Email gateway",
                                "Mail server",
                                "Network intrusion detection system",
                                "Detonation chamber",
                                "SSL/TLS inspection",
                                "Anti-virus"
                            ],
                            "x_mitre_detection": "Network intrusion detection systems and email gateways can be used to detect phishing with malicious attachments in transit. Detonation chambers may also be used to identify malicious attachments. Solutions can be signature and behavior based, but adversaries may construct attachments in a way to avoid these systems.\n\nURL inspection within email (including expanding shortened links) can help detect links leading to known malicious sites. Detonation chambers can be used to detect these links and either automatically go to these sites to determine if they're potentially malicious, or wait and capture the content if a user visits the link.\n\nBecause most common third-party services used for phishing via service leverage TLS encryption, SSL/TLS inspection is generally required to detect the initial communication/delivery. With SSL/TLS inspection intrusion detection signatures or other security gateway appliances may be able to detect malware.\n\nAnti-virus can potentially detect malicious documents and files that are downloaded on the user's computer. Many possible detections of follow-on behavior may take place once [User Execution](https://attack.mitre.org/techniques/T1204) occurs.",
                            "x_mitre_is_subtechnique": false,
                            "x_mitre_platforms": [
                                "Linux",
                                "macOS",
                                "Windows",
                                "SaaS",
                                "Office 365"
                            ],
                            "x_mitre_version": "2.0"
                        },
                        {
                            "created": "2022-10-06T13:54:38.524424Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--963bc48e-f0a9-4dca-9c35-5c359c56702d",
                            "lang": "en",
                            "modified": "2022-10-06T13:54:38.524437Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "indicates",
                            "revoked": false,
                            "source_ref": "indicator--e4055cbb-0921-4282-8257-1dc8feb21fd9",
                            "spec_version": "2.1",
                            "start_time": "2022-10-06T00:00:00Z",
                            "stop_time": "2023-04-04T00:00:00Z",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "relationship--de4bf4da-8611-4974-b3a6-eeddc9c0e85e"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--337e49ec-fd09-4137-b795-23ced297eb46",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--20224f11-35cc-419b-8400-7ac4a1b5fcfc",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--27b80b5d-33d3-458f-ab8d-ceef9cc67a73",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--65f56a7a-c52d-490c-bb24-7f938a9f8b3c",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--3b11929b-f582-40ef-8bf9-e164f9e98533",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--8d676ee1-2a22-488f-bdc4-ceedba0dc9fc",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9a88ee06-4fa5-4df8-87a1-bfebee73571f",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--e9d6e91b-a985-4bc7-877b-eba895611b82",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--fe17c312-6959-47e1-add0-c646a58ba9b3",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--135c841a-fa34-4458-a0a2-b5a5e4653a69",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--e750e75f-a687-44f0-892f-bb27c5d7caf2",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--09551288-c63a-4d0f-916c-4a2869f8d13f",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                                "identity--35b29d72-54a3-4568-adf8-c6a0d41e3087",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--09d3cafb-b139-46ad-a13b-0b03f4e88ed6",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--940dffc4-5d82-41fc-add0-1685a155f7c8",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--1b384f3f-d25c-4bf7-82fc-423dce5765d5",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--bf39eb1f-76f0-425a-ac92-bcbee80ad111",
                                "identity--7681454e-daac-46ee-bd4e-5904a2f1043d",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8d0115ae-e9e5-46b4-8000-ee45a1549118",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--2ce5c3b6-e96f-40e4-b180-adb96d191ea6",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--d4e6daf6-6e06-4904-bf82-76d331ba491c"
                            ]
                        },
                        {
                            "action_type": "textual:text/md",
                            "confidence": 100,
                            "created": "2020-02-21T15:07:07.442223Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "course-of-action--c25c8979-693f-45a1-a823-b4453acd57b1",
                            "lang": "en",
                            "modified": "2020-02-21T15:09:38.134092Z",
                            "name": "Block network traffic to the malicious domains, URLs, addresses listed in the technical details",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e95a2ded-df98-4ea7-be39-d2a0b20b885d",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--fed52e08-bb9e-454b-b2cf-7c05cd846185",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--47bd9f79-6d32-4a6b-b148-05c20ee8c75c",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--87e52b9a-0684-4fdf-9bc8-d7e0644bcc7a",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "created": "2021-03-17T15:56:48.102985Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--14c8602c-7ea7-445e-a450-fa1270700a98",
                            "lang": "en",
                            "modified": "2021-03-17T20:00:13.612535Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--c25c8979-693f-45a1-a823-b4453acd57b1",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "action_type": "textual:text/md",
                            "confidence": 100,
                            "created": "2019-10-24T12:51:37.147439Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Educate employees to report suspicious emails and avoid clicking on attached files in case of any doubt.",
                            "id": "course-of-action--175183cd-8d64-447d-8e34-295354d25448",
                            "lang": "en",
                            "modified": "2019-12-02T16:57:37.148097Z",
                            "name": "Education",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e95a2ded-df98-4ea7-be39-d2a0b20b885d",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--a6419448-76ec-4fa9-892e-d05c7ec055d9",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--3e4729c7-df58-4b2b-986b-4ee8e17e905b",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--fed52e08-bb9e-454b-b2cf-7c05cd846185",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--337e49ec-fd09-4137-b795-23ced297eb46",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--b0e2d35c-c823-44ce-aff6-1dee3f711ba9",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--c638c842-3d89-46ca-88d5-dce2d53c02b5",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--47bd9f79-6d32-4a6b-b148-05c20ee8c75c",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--05961d5c-9970-4fa8-a0dc-4794b1edba6a",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--23168672-6c82-491e-8da2-fb6c5721d04f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--9a88ee06-4fa5-4df8-87a1-bfebee73571f",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--87e52b9a-0684-4fdf-9bc8-d7e0644bcc7a",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "confidence": 90,
                            "created": "2021-03-17T15:56:48.102907Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--60ba09cf-9a5b-4746-9bb8-e2b76f85a99c",
                            "lang": "en",
                            "modified": "2021-10-12T15:12:46.084516Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--175183cd-8d64-447d-8e34-295354d25448",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "action_bin": "Investigate new email rules, email filters or email forwarding actions.",
                            "action_type": "textual:text/md",
                            "created": "2019-12-02T16:39:44.020088Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Monitor email server logs for suspicious connections, emails rules creation or filter creation, or automatic forwarding of emails.",
                            "id": "course-of-action--9f28db66-61d4-4cb3-9940-8e6af7e85d80",
                            "lang": "en",
                            "modified": "2019-12-02T16:57:37.14813Z",
                            "name": "Monitor email server logs",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "confidence": 70,
                            "created": "2021-10-25T09:16:09.886986Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--e836a902-b517-4f8e-ba4d-f2fe7a8b36a7",
                            "lang": "en",
                            "modified": "2021-10-25T11:56:46.719178Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--9f28db66-61d4-4cb3-9940-8e6af7e85d80",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--b646afaa-1f1d-4bb2-9018-883d78f287b8"
                            ]
                        },
                        {
                            "action_bin": "",
                            "action_type": "textual:text/md",
                            "created": "2019-11-08T10:52:04.556728Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Use signatures or heuristics to detect malicious software.",
                            "external_references": [
                                {
                                    "external_id": "M1049",
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/mitigations/M1049"
                                }
                            ],
                            "id": "course-of-action--ab23f054-fc61-4d83-9a7e-a0794a6f051b",
                            "lang": "en",
                            "modified": "2021-07-07T13:59:54.193133Z",
                            "name": "Antivirus/Antimalware",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "course-of-action--ab23f054-fc61-4d83-9a7e-a0794a6f051b"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e95a2ded-df98-4ea7-be39-d2a0b20b885d",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--a6419448-76ec-4fa9-892e-d05c7ec055d9",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a4804e0e-c7aa-4c8a-b0b3-0031bb396128",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--fed52e08-bb9e-454b-b2cf-7c05cd846185",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--3e4729c7-df58-4b2b-986b-4ee8e17e905b",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--97287f3b-07c2-4777-838b-d6cd00ebaccb",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--2adc0f69-709c-4651-aa73-c0fd063be173",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--07888608-174b-40a3-8f61-ecfbde26cf36",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--c13c5ebf-9d56-4625-bd76-fb53d61587b7",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--0ea15bef-04a4-4b10-9697-d40f0ac54deb",
                                "location--312b214e-d9ce-4b9d-a3ed-12b49043928c",
                                "location--7532d11a-30db-46dc-8dae-b2595ffe2672",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--604ec07c-cb93-4129-a68b-5a33883e11b6",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--a0caf772-475b-44cb-a1af-ae1debc29d87",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--c638c842-3d89-46ca-88d5-dce2d53c02b5",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--9f79a366-6f5b-4f3f-9928-9cc7316b2a8d",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--47bd9f79-6d32-4a6b-b148-05c20ee8c75c",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--27b80b5d-33d3-458f-ab8d-ceef9cc67a73",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--65f56a7a-c52d-490c-bb24-7f938a9f8b3c",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--9a88ee06-4fa5-4df8-87a1-bfebee73571f",
                                "location--23168672-6c82-491e-8da2-fb6c5721d04f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--3b11929b-f582-40ef-8bf9-e164f9e98533",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--7af531f7-4ded-4ee6-b812-14796f61bc07",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--87e52b9a-0684-4fdf-9bc8-d7e0644bcc7a",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ],
                            "x_mitre_version": "1.1"
                        },
                        {
                            "created": "2020-08-27T16:07:01.191545Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Anti-virus can automatically quarantine suspicious files.",
                            "id": "relationship--0476f051-b530-4cd1-bf42-368eea4d7bc9",
                            "lang": "en",
                            "modified": "2021-11-23T10:03:31.004728Z",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--ab23f054-fc61-4d83-9a7e-a0794a6f051b",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "relationship--ed821f5e-9527-4fbb-ae76-37a79592dfb6"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_attack_spec_version": "2.1.0",
                            "x_mitre_domains": [
                                "enterprise-attack"
                            ],
                            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "x_mitre_version": "1.0"
                        },
                        {
                            "action_bin": "",
                            "action_type": "textual:text/md",
                            "created": "2019-11-08T10:52:04.557697Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Use intrusion detection signatures to block traffic at network boundaries.",
                            "external_references": [
                                {
                                    "external_id": "M1031",
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/mitigations/M1031"
                                }
                            ],
                            "id": "course-of-action--63106058-cc49-4edb-a058-108998ba1b2d",
                            "lang": "en",
                            "modified": "2021-06-25T13:28:51.049008Z",
                            "name": "Network Intrusion Prevention",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "course-of-action--63106058-cc49-4edb-a058-108998ba1b2d"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e95a2ded-df98-4ea7-be39-d2a0b20b885d",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--a6419448-76ec-4fa9-892e-d05c7ec055d9",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--fed52e08-bb9e-454b-b2cf-7c05cd846185",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--3e4729c7-df58-4b2b-986b-4ee8e17e905b",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--2adc0f69-709c-4651-aa73-c0fd063be173",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--07888608-174b-40a3-8f61-ecfbde26cf36",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--312b214e-d9ce-4b9d-a3ed-12b49043928c",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--a0caf772-475b-44cb-a1af-ae1debc29d87",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--c638c842-3d89-46ca-88d5-dce2d53c02b5",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--47bd9f79-6d32-4a6b-b148-05c20ee8c75c",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--87e52b9a-0684-4fdf-9bc8-d7e0644bcc7a",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ],
                            "x_mitre_version": "1.0"
                        },
                        {
                            "created": "2020-08-27T16:07:01.191558Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Network intrusion prevention systems and systems designed to scan and remove malicious email attachments or links can be used to block activity.",
                            "id": "relationship--b375ed3d-c9ba-4f58-afbd-5b36ff53efec",
                            "lang": "en",
                            "modified": "2021-11-23T10:03:31.00474Z",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--63106058-cc49-4edb-a058-108998ba1b2d",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "relationship--76588f90-79b8-4a61-ae07-3321393e5707"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_attack_spec_version": "2.1.0",
                            "x_mitre_domains": [
                                "enterprise-attack"
                            ],
                            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "x_mitre_version": "1.0"
                        },
                        {
                            "action_bin": "",
                            "action_type": "textual:text/md",
                            "created": "2019-11-08T10:52:04.558076Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc.",
                            "external_references": [
                                {
                                    "external_id": "M1021",
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/mitigations/M1021"
                                }
                            ],
                            "id": "course-of-action--ee90300a-12fc-4c62-a00b-360958bb7b5b",
                            "lang": "en",
                            "modified": "2021-11-23T09:13:59.889266Z",
                            "name": "Restrict Web-Based Content",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e95a2ded-df98-4ea7-be39-d2a0b20b885d",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--312b214e-d9ce-4b9d-a3ed-12b49043928c",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--47bd9f79-6d32-4a6b-b148-05c20ee8c75c",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--87e52b9a-0684-4fdf-9bc8-d7e0644bcc7a",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_attack_spec_version": "2.1.0",
                            "x_mitre_domains": [
                                "enterprise-attack"
                            ],
                            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "x_mitre_version": "1.0"
                        },
                        {
                            "created": "2020-08-27T16:07:01.19157Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Determine if certain websites or attachment types (ex: .scr, .exe, .pif, .cpl, etc.) that can be used for phishing are necessary for business operations and consider blocking access if activity cannot be monitored well or if it poses a significant risk.",
                            "id": "relationship--d71f58b5-023e-4ace-8694-6a8a968cfda0",
                            "lang": "en",
                            "modified": "2021-11-23T10:03:31.004752Z",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--ee90300a-12fc-4c62-a00b-360958bb7b5b",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "relationship--a205b0ce-df00-40ae-b626-7dc3e8146d45"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_attack_spec_version": "2.1.0",
                            "x_mitre_domains": [
                                "enterprise-attack"
                            ],
                            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "x_mitre_version": "1.0"
                        },
                        {
                            "action_bin": "",
                            "action_type": "textual:text/md",
                            "created": "2019-07-19T16:19:42.117804Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Describes any guidance or training given to users to set particular configuration settings or avoid specific potentially risky behaviors.",
                            "external_references": [
                                {
                                    "external_id": "M1011",
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/mitigations/M1011"
                                }
                            ],
                            "id": "course-of-action--158429d1-e0b3-4144-9044-10a4288095fc",
                            "lang": "en",
                            "modified": "2020-08-27T16:55:34.011703Z",
                            "name": "User Guidance",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_old_attack_id": "MOB-M1011",
                            "x_mitre_version": "1.0"
                        },
                        {
                            "created": "2022-01-24T16:14:57.254916Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--bec94729-0571-4452-a6c1-bdddc1c88aa6",
                            "lang": "en",
                            "modified": "2022-01-24T16:14:57.254929Z",
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--158429d1-e0b3-4144-9044-10a4288095fc",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd"
                            ],
                            "x_ic_is_in_flint": false
                        },
                        {
                            "action_bin": "",
                            "action_type": "textual:text/md",
                            "created": "2019-11-08T10:52:04.558131Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates.",
                            "external_references": [
                                {
                                    "external_id": "M1054",
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/mitigations/M1054"
                                }
                            ],
                            "id": "course-of-action--bdf91c1e-a417-4d9c-8eaa-5c9812562391",
                            "lang": "en",
                            "modified": "2021-11-23T09:13:59.889519Z",
                            "name": "Software Configuration",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--fed52e08-bb9e-454b-b2cf-7c05cd846185",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_attack_spec_version": "2.1.0",
                            "x_mitre_domains": [
                                "enterprise-attack"
                            ],
                            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "x_mitre_version": "1.1"
                        },
                        {
                            "confidence": 100,
                            "created": "2021-11-23T09:14:15.123024Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.(Citation: Microsoft Anti Spoofing)(Citation: ACSC Email Spoofing)",
                            "id": "relationship--8fe853b4-b32f-423b-a39c-c47f2973808c",
                            "lang": "en",
                            "modified": "2022-03-23T13:59:42.620647Z",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--bdf91c1e-a417-4d9c-8eaa-5c9812562391",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "relationship--7b090d29-d49d-4967-9843-90636bfb039f"
                            ],
                            "x_ic_impacted_locations": [
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_attack_spec_version": "2.1.0",
                            "x_mitre_domains": [
                                "enterprise-attack"
                            ],
                            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "x_mitre_version": "1.0"
                        },
                        {
                            "action_bin": "",
                            "action_type": "textual:text/md",
                            "confidence": 100,
                            "created": "2019-11-08T10:52:04.557666Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Use two (2FA) or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.",
                            "external_references": [
                                {
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/mitigations/M1032"
                                }
                            ],
                            "id": "course-of-action--2e2e9bd1-e2ba-4eb9-b145-a735b0758dd4",
                            "lang": "en",
                            "modified": "2022-03-31T07:47:34.663205Z",
                            "name": "Multi-factor Authentication (2FA)",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "course-of-action--2e2e9bd1-e2ba-4eb9-b145-a735b0758dd4"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e95a2ded-df98-4ea7-be39-d2a0b20b885d",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--a6419448-76ec-4fa9-892e-d05c7ec055d9",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a4804e0e-c7aa-4c8a-b0b3-0031bb396128",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--b0e2d35c-c823-44ce-aff6-1dee3f711ba9",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--97287f3b-07c2-4777-838b-d6cd00ebaccb",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--fed52e08-bb9e-454b-b2cf-7c05cd846185",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--337e49ec-fd09-4137-b795-23ced297eb46",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--2e355574-1019-47ef-ab6d-1a990d1d4407",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--2adc0f69-709c-4651-aa73-c0fd063be173",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--c638c842-3d89-46ca-88d5-dce2d53c02b5",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--604ec07c-cb93-4129-a68b-5a33883e11b6",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--a0caf772-475b-44cb-a1af-ae1debc29d87",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--02e27ed9-728e-4bfa-9639-481a5692c960",
                                "location--c13c5ebf-9d56-4625-bd76-fb53d61587b7",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--9f79a366-6f5b-4f3f-9928-9cc7316b2a8d",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--7532d11a-30db-46dc-8dae-b2595ffe2672",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--07888608-174b-40a3-8f61-ecfbde26cf36",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--312b214e-d9ce-4b9d-a3ed-12b49043928c",
                                "location--0ea15bef-04a4-4b10-9697-d40f0ac54deb",
                                "location--3e4729c7-df58-4b2b-986b-4ee8e17e905b",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--05961d5c-9970-4fa8-a0dc-4794b1edba6a",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--3b11929b-f582-40ef-8bf9-e164f9e98533",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--47bd9f79-6d32-4a6b-b148-05c20ee8c75c",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--27b80b5d-33d3-458f-ab8d-ceef9cc67a73",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--65f56a7a-c52d-490c-bb24-7f938a9f8b3c",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--9a88ee06-4fa5-4df8-87a1-bfebee73571f",
                                "location--23168672-6c82-491e-8da2-fb6c5721d04f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--7af531f7-4ded-4ee6-b812-14796f61bc07",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--87e52b9a-0684-4fdf-9bc8-d7e0644bcc7a"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ],
                            "x_mitre_version": "1.0"
                        },
                        {
                            "confidence": 70,
                            "created": "2020-10-21T16:22:30.102054Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--fad729e1-ca31-41ef-b99f-3f42a9cac8a8",
                            "lang": "en",
                            "modified": "2022-04-26T07:18:33.999988Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--2e2e9bd1-e2ba-4eb9-b145-a735b0758dd4",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--1f86d874-9e74-4105-a8d3-98bf256ea9b5",
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                                "identity--498aae66-3ce0-47e1-b3fb-9f08a73865f0",
                                "identity--4f328c25-5af1-42d2-89e2-b8bd163eb3f6",
                                "identity--6bc0f5eb-c8b7-4821-8349-222823a03630",
                                "identity--902a7c83-b3be-4630-9ee6-629663579705",
                                "identity--956dd012-6723-466f-9742-869c7b91a84a",
                                "identity--b646afaa-1f1d-4bb2-9018-883d78f287b8",
                                "identity--f0275bd2-b2ac-4162-a6e1-12624efc9af4",
                                "identity--fda6599d-3337-4fc0-bdac-4837e4ef6297"
                            ]
                        },
                        {
                            "action_bin": "",
                            "action_type": "textual:text/md",
                            "created": "2019-11-08T10:52:04.558268Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction.",
                            "external_references": [
                                {
                                    "external_id": "M1017",
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/mitigations/M1017"
                                }
                            ],
                            "id": "course-of-action--6c2383bb-f100-4404-8dbc-f0fad80e59eb",
                            "lang": "en",
                            "modified": "2021-11-23T09:13:59.889925Z",
                            "name": "User Training",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "course-of-action",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--e95a2ded-df98-4ea7-be39-d2a0b20b885d",
                                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--a6419448-76ec-4fa9-892e-d05c7ec055d9",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a4804e0e-c7aa-4c8a-b0b3-0031bb396128",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--b0e2d35c-c823-44ce-aff6-1dee3f711ba9",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--fed52e08-bb9e-454b-b2cf-7c05cd846185",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--337e49ec-fd09-4137-b795-23ced297eb46",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--2e355574-1019-47ef-ab6d-1a990d1d4407",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--97287f3b-07c2-4777-838b-d6cd00ebaccb",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--2adc0f69-709c-4651-aa73-c0fd063be173",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--c638c842-3d89-46ca-88d5-dce2d53c02b5",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--a0caf772-475b-44cb-a1af-ae1debc29d87",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                                "location--02e27ed9-728e-4bfa-9639-481a5692c960",
                                "location--c13c5ebf-9d56-4625-bd76-fb53d61587b7",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--9f79a366-6f5b-4f3f-9928-9cc7316b2a8d",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--07888608-174b-40a3-8f61-ecfbde26cf36",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--312b214e-d9ce-4b9d-a3ed-12b49043928c",
                                "location--0ea15bef-04a4-4b10-9697-d40f0ac54deb",
                                "location--3e4729c7-df58-4b2b-986b-4ee8e17e905b",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--05961d5c-9970-4fa8-a0dc-4794b1edba6a",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--3b11929b-f582-40ef-8bf9-e164f9e98533",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--47bd9f79-6d32-4a6b-b148-05c20ee8c75c",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--5e85e2d6-f14b-4219-b15d-e2c573ddba0c",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--27b80b5d-33d3-458f-ab8d-ceef9cc67a73",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--9a88ee06-4fa5-4df8-87a1-bfebee73571f",
                                "location--23168672-6c82-491e-8da2-fb6c5721d04f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--87e52b9a-0684-4fdf-9bc8-d7e0644bcc7a",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
                            ],
                            "x_mitre_attack_spec_version": "2.1.0",
                            "x_mitre_domains": [
                                "enterprise-attack"
                            ],
                            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "x_mitre_version": "1.2"
                        },
                        {
                            "confidence": 90,
                            "created": "2020-08-27T16:07:01.191588Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Users can be trained to identify social engineering techniques and phishing emails.",
                            "id": "relationship--25557ec8-0fe0-4d7e-8d9f-f02baad96d8d",
                            "lang": "en",
                            "modified": "2022-09-14T13:01:36.33534Z",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "relationship_type": "mitigates",
                            "revoked": false,
                            "source_ref": "course-of-action--6c2383bb-f100-4404-8dbc-f0fad80e59eb",
                            "spec_version": "2.1",
                            "target_ref": "attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--02b69288-ed1c-434a-a9df-434920d43283",
                                "identity--1f86d874-9e74-4105-a8d3-98bf256ea9b5",
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                                "identity--498aae66-3ce0-47e1-b3fb-9f08a73865f0",
                                "identity--4f328c25-5af1-42d2-89e2-b8bd163eb3f6",
                                "identity--6bc0f5eb-c8b7-4821-8349-222823a03630",
                                "identity--902a7c83-b3be-4630-9ee6-629663579705",
                                "identity--956dd012-6723-466f-9742-869c7b91a84a",
                                "identity--f0275bd2-b2ac-4162-a6e1-12624efc9af4",
                                "identity--fda6599d-3337-4fc0-bdac-4837e4ef6297"
                            ]
                        },
                        {
                            "confidence": 80,
                            "created": "2021-05-18T10:09:02.765927Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "identity--02b69288-ed1c-434a-a9df-434920d43283",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-02-24T12:43:48.741259Z",
                            "name": "www.ic3.gov",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true
                        },
                        {
                            "confidence": 70,
                            "contact_information": "www.nationalcrimeagency.gov.uk",
                            "created": "2022-04-21T16:06:05.133195Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "National Crime Agency UK",
                            "id": "identity--1f86d874-9e74-4105-a8d3-98bf256ea9b5",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-04-26T07:18:33.463293Z",
                            "name": "nationalcrimeagency.gov.uk",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true,
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
                            "confidence": 90,
                            "created": "2020-07-27T15:09:09.881521Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "identity--498aae66-3ce0-47e1-b3fb-9f08a73865f0",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-02-24T12:43:48.741503Z",
                            "name": "www.ncsc.gov.uk",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true
                        },
                        {
                            "confidence": 90,
                            "created": "2020-07-29T15:38:09.564354Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "identity--4f328c25-5af1-42d2-89e2-b8bd163eb3f6",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2021-09-17T09:33:30.239056Z",
                            "name": "www.fbi.gov",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true
                        },
                        {
                            "confidence": 100,
                            "created": "2020-05-26T13:43:04.899719Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Australian Cyber Security Centre (ACSC)",
                            "id": "identity--6bc0f5eb-c8b7-4821-8349-222823a03630",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-09-20T12:56:24.80827Z",
                            "name": "www.cyber.gov.au",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true
                        },
                        {
                            "confidence": 100,
                            "created": "2022-01-12T08:14:45.889905Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "The National Security Agency/Central Security Service (NSA/CSS) leads the U.S. Government in cryptology that encompasses both signals intelligence (SIGINT) insights and cybersecurity products and services and enables computer network operations to gain a decisive advantage for the nation and our allies. ",
                            "external_references": [
                                {
                                    "description": "",
                                    "source_name": "NSA website",
                                    "url": "www.nsa.gov"
                                }
                            ],
                            "id": "identity--902a7c83-b3be-4630-9ee6-629663579705",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-01-12T08:14:53.787499Z",
                            "name": "www.nsa.gov",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "sectors": [
                                "defence"
                            ],
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "confidence": 70,
                            "contact_information": "https://cyber.gc.ca/en/",
                            "created": "2022-04-21T16:18:07.924815Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Canadian Centre for Cyber Security",
                            "id": "identity--956dd012-6723-466f-9742-869c7b91a84a",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-09-20T12:56:24.808282Z",
                            "name": "cyber.gc.ca",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "confidence": 90,
                            "created": "2020-09-14T08:34:27.53197Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "identity--b646afaa-1f1d-4bb2-9018-883d78f287b8",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-02-24T12:43:48.741492Z",
                            "name": "www.microsoft.com",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true
                        },
                        {
                            "confidence": 92,
                            "created": "2017-06-01T00:00:00Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2020-04-08T14:28:56.293499Z",
                            "name": "The MITRE Corporation",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true
                        },
                        {
                            "confidence": 50,
                            "contact_information": "https://www.phishtank.com/",
                            "created": "2020-10-12T15:04:56.036584Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "PhishTank is a collaborative clearing house for data and information about phishing on the Internet.\n\nIOCs from PhishTank are automatically added to IntelligenceCenter by playbook.",
                            "external_references": [
                                {
                                    "source_name": "phishtank.org",
                                    "url": "https://phishtank.org/"
                                }
                            ],
                            "id": "identity--d4e6daf6-6e06-4904-bf82-76d331ba491c",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-04-06T14:37:31.26237Z",
                            "name": "PhishTank",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true
                        },
                        {
                            "confidence": 70,
                            "created": "2021-12-16T09:16:48.95929Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "identity--f0275bd2-b2ac-4162-a6e1-12624efc9af4",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-02-25T10:14:35.647596Z",
                            "name": "www.cisa.gov",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true
                        },
                        {
                            "confidence": 70,
                            "contact_information": "https://www.ncsc.govt.nz/",
                            "created": "2022-04-21T16:04:53.593739Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "NCSC NZ",
                            "id": "identity--fda6599d-3337-4fc0-bdac-4837e4ef6297",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-04-26T07:18:33.463271Z",
                            "name": "ncsc.govt.nz",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
                            "x_ic_is_sector": false,
                            "x_ic_is_source": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
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
        },
        "URL": {
            "confidence": 70,
            "created": "2022-10-06T13:54:38.493542Z",
            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
            "id": "indicator--e4055cbb-0921-4282-8257-1dc8feb21fd9",
            "indicator_types": [
                "malicious-activity"
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                    "phase_name": "delivery"
                },
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access"
                }
            ],
            "lang": "en",
            "modified": "2022-10-06T13:54:38.493555Z",
            "name": "http://truesec.pro/",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
            "pattern": "[url:value = 'http://truesec.pro/']",
            "pattern_type": "stix",
            "revoked": false,
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2022-10-06T00:00:00Z",
            "valid_until": "2023-04-04T00:00:00Z",
            "x_ic_deprecated": false,
            "x_ic_external_refs": [
                "indicator--fcda35a2-f982-4311-9295-de89ab0165ab"
            ],
            "x_ic_impacted_locations": [
                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                "location--f2e7bf25-010f-4633-b2ec-afc4eafe9cee",
                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                "location--e3a75103-d5c3-45f2-955c-52d164edf5be",
                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                "location--cafa8eec-a9bd-4b49-bb78-bf9c88dd8933",
                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                "location--b9c12531-454c-44a9-8317-63a975993e11",
                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                "location--b9b060b9-6dc0-4178-9761-74c77853ddbb",
                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                "location--ccb4e564-ac74-4500-8baf-e86290f7fa3a",
                "location--49acb0ca-5bff-4f1f-9df8-a079fce86e0e",
                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                "location--3941c409-d9a7-4ba1-b456-524331aec591",
                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                "location--337e49ec-fd09-4137-b795-23ced297eb46",
                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                "location--0e173f6e-b201-4c91-8576-cf415bed1c7f",
                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                "location--c10f2499-a30d-4192-b625-8dac29801910",
                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                "location--339d05db-907d-49a3-b699-de004149adb7",
                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                "location--092a468b-54e1-4199-9737-7268c84115bd",
                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                "location--20224f11-35cc-419b-8400-7ac4a1b5fcfc",
                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                "location--52ded424-48e2-428d-8244-150b0afc6920",
                "location--079c1553-452c-4890-8341-1acecdcaf851",
                "location--2e27be15-25f8-4284-81bf-c9c221d2ce97",
                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                "location--27b80b5d-33d3-458f-ab8d-ceef9cc67a73",
                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                "location--5fa6f044-1427-4b43-8ce5-78f21bfcb7d0",
                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                "location--65f56a7a-c52d-490c-bb24-7f938a9f8b3c",
                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                "location--af554517-cec1-44a8-af43-111b92b380c7",
                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                "location--6a5a91ac-0a37-4973-bd7c-115d36522912",
                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                "location--6eba0ae2-e33e-4f96-9051-382ff4e86702",
                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                "location--3b11929b-f582-40ef-8bf9-e164f9e98533",
                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                "location--d5bd45bc-3fac-43ac-af60-39bb3b842317",
                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                "location--8d676ee1-2a22-488f-bdc4-ceedba0dc9fc",
                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                "location--9a88ee06-4fa5-4df8-87a1-bfebee73571f",
                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                "location--a5013209-3177-4642-90c5-9a3884717b4e"
            ],
            "x_ic_impacted_sectors": [
                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd",
                "identity--cfda7cae-9f40-4028-916e-95b9b4e44e8b",
                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                "identity--e9d6e91b-a985-4bc7-877b-eba895611b82",
                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                "identity--fe17c312-6959-47e1-add0-c646a58ba9b3",
                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                "identity--135c841a-fa34-4458-a0a2-b5a5e4653a69",
                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                "identity--e750e75f-a687-44f0-892f-bb27c5d7caf2",
                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                "identity--09551288-c63a-4d0f-916c-4a2869f8d13f",
                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                "identity--35b29d72-54a3-4568-adf8-c6a0d41e3087",
                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                "identity--09d3cafb-b139-46ad-a13b-0b03f4e88ed6",
                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                "identity--940dffc4-5d82-41fc-add0-1685a155f7c8",
                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                "identity--1b384f3f-d25c-4bf7-82fc-423dce5765d5",
                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                "identity--8f9dece2-2841-40db-b242-1cc709b6ff59",
                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                "identity--bf39eb1f-76f0-425a-ac92-bcbee80ad111",
                "identity--7681454e-daac-46ee-bd4e-5904a2f1043d",
                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                "identity--8d0115ae-e9e5-46b4-8000-ee45a1549118",
                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                "identity--2ce5c3b6-e96f-40e4-b180-adb96d191ea6",
                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63"
            ],
            "x_ic_is_in_flint": false,
            "x_ic_observable_types": [
                "url"
            ],
            "x_inthreat_sources_refs": [
                "identity--d4e6daf6-6e06-4904-bf82-76d331ba491c"
            ]
        }
    },
    "URL": {
        "Data": "http://truesec.pro/",
        "TrafficLightProtocol": "white"
    }
}
```

#### Human Readable Output

>### Indicator <http://truesec.pro/> is linked to the following:

>|name|description|type|aliases|goals|revoked|created|modified|more_info|
>|---|---|---|---|---|---|---|---|---|
>| Phishing | Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.<br/><br/>Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems or to gather credentials for use of [Valid Accounts](https://attack.mitre.org/techniques/T1078). Phishing may also be conducted via third-party services, like social media platforms. | attack-pattern |  |  | false | 2020-08-27T16:06:57.165806Z | 2022-01-28T08:06:15.568392Z | [More info about Phishing on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/attack-pattern--a5911dd1-af0e-4164-a099-a1fa4909e42e) |


### domain

***
Query SEKOIA.IO Intelligence Center for information about this indicator. No information is returned if the value is not a known by SEKOIA.IO as an indicator (IoC). STIX IDs can be resolved from SEKOIA.IO Intelligence Center application.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Indicator value. | Required | 


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
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example

```!domain domain="eicar.sekoia.io"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "eicar.sekoia.io",
        "Reliability": "F - Reliability cannot be judged",
        "Score": 1,
        "Type": "domain",
        "Vendor": "SEKOIAIntelligenceCenter"
    },
    "Domain": {
        "Name": "eicar.sekoia.io",
        "TrafficLightProtocol": "green"
    },
    "SEKOIAIntelligenceCenter": {
        "Domain": {
            "confidence": 100,
            "created": "2020-05-25T07:17:55.573191Z",
            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
            "description": "This domain name is associated with the C&C server of the SEKOIA EICAR campaign.\n\nThe webserver is not responding when the campaign is run in inoculated mode.",
            "id": "indicator--ec6fdd6f-8fa0-4a57-b844-1399efe65a95",
            "indicator_types": [
                "benign"
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                    "phase_name": "command-and-control"
                }
            ],
            "lang": "en",
            "modified": "2022-01-25T14:03:55.974114Z",
            "name": "eicar.sekoia.io",
            "object_marking_refs": [
                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
            ],
            "pattern": "[domain-name:value = 'eicar.sekoia.io']",
            "pattern_type": "stix",
            "revoked": false,
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2020-05-25T00:00:00Z",
            "valid_until": "2025-06-01T00:00:00Z",
            "x_ic_deprecated": false,
            "x_ic_impacted_locations": [
                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                "location--b9c12531-454c-44a9-8317-63a975993e11",
                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                "location--079c1553-452c-4890-8341-1acecdcaf851",
                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                "location--b2f21856-d558-4904-bbe7-f832af1adc2a"
            ],
            "x_ic_impacted_sectors": [
                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                "identity--499a1938-8f6f-4023-82a1-56400e42d697"
            ],
            "x_ic_is_in_flint": false,
            "x_ic_observable_types": [
                "domain-name"
            ],
            "x_inthreat_sources_refs": [
                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
            ]
        },
        "IndicatorContext": {
            "indicator": {
                "type": "domain-name",
                "value": "eicar.sekoia.io"
            },
            "items": [
                {
                    "id": "bundle--e7e77c83-6822-40f3-ab2e-edd4df4f1265",
                    "objects": [
                        {
                            "confidence": 100,
                            "created": "2020-05-25T07:17:55.573191Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "This domain name is associated with the C&C server of the SEKOIA EICAR campaign.\n\nThe webserver is not responding when the campaign is run in inoculated mode.",
                            "id": "indicator--ec6fdd6f-8fa0-4a57-b844-1399efe65a95",
                            "indicator_types": [
                                "benign"
                            ],
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "command-and-control"
                                }
                            ],
                            "lang": "en",
                            "modified": "2022-01-25T14:03:55.974114Z",
                            "name": "eicar.sekoia.io",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "pattern": "[domain-name:value = 'eicar.sekoia.io']",
                            "pattern_type": "stix",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "indicator",
                            "valid_from": "2020-05-25T00:00:00Z",
                            "valid_until": "2025-06-01T00:00:00Z",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_ic_observable_types": [
                                "domain-name"
                            ],
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "aliases": [
                                "EICAR",
                                "Malware TEST EICAR SEKOIA.IO",
                                "Dropper TEST EICAR SEKOIA.IO"
                            ],
                            "created": "2020-05-26T13:19:41.236073Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "*Context*\nThis Dropper is used by SEKOIA Red Team as a demonstration to illustrate how an inoculated file could also be used as a malicious file to install dangerous content onto the corporate  environment.\n\n*Execution stages*\nThis dropper is known to be distributed as a Powershell script.\n- At execution, it drops a text payload (inoculated payload part of the EICAR campaign)\n- If Internet connectivity is available, the dropper contacts a Command and control server to  install additional modules (deactivated in the EICAR campaign) \n",
                            "external_references": [
                                {
                                    "description": "",
                                    "source_name": "EICAR Test ",
                                    "url": "https://en.wikipedia.org/wiki/EICAR_test_file"
                                }
                            ],
                            "id": "malware--2850a39e-39a1-4701-a3cc-185478464dc5",
                            "is_family": true,
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "command-and-control"
                                },
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "actions-on-objectives"
                                }
                            ],
                            "lang": "en",
                            "malware_types": [
                                "dropper"
                            ],
                            "modified": "2020-06-22T09:09:28.349981Z",
                            "more_info": "[More info about Dropper TEST EICAR SEKOIA.IO on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/malware--2850a39e-39a1-4701-a3cc-185478464dc5)",
                            "name": "Dropper TEST EICAR SEKOIA.IO",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "malware",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ]
                        },
                        {
                            "created": "2020-05-26T13:24:08.945113Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--5ea3c956-792c-4ab2-a2cf-c67e707ebba0",
                            "lang": "en",
                            "modified": "2020-05-29T09:00:40.635811Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "indicates",
                            "revoked": false,
                            "source_ref": "indicator--ec6fdd6f-8fa0-4a57-b844-1399efe65a95",
                            "spec_version": "2.1",
                            "start_time": "2020-05-25T00:00:00Z",
                            "stop_time": "2025-06-01T00:00:00Z",
                            "target_ref": "malware--2850a39e-39a1-4701-a3cc-185478464dc5",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697"
                            ],
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

>### Indicator eicar.sekoia.io is linked to the following:

>|name|description|type|aliases|goals|revoked|created|modified|more_info|
>|---|---|---|---|---|---|---|---|---|
>| Dropper TEST EICAR SEKOIA.IO | *Context*<br/>This Dropper is used by SEKOIA Red Team as a demonstration to illustrate how an inoculated file could also be used as a malicious file to install dangerous content onto the corporate  environment.<br/><br/>*Execution stages*<br/>This dropper is known to be distributed as a Powershell script.<br/>- At execution, it drops a text payload (inoculated payload part of the EICAR campaign)<br/>- If Internet connectivity is available, the dropper contacts a Command and control server to  install additional modules (deactivated in the EICAR campaign) <br/> | malware | EICAR,<br/>Malware TEST EICAR SEKOIA.IO,<br/>Dropper TEST EICAR SEKOIA.IO |  | false | 2020-05-26T13:19:41.236073Z | 2020-06-22T09:09:28.349981Z | [More info about Dropper TEST EICAR SEKOIA.IO on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/malware--2850a39e-39a1-4701-a3cc-185478464dc5) |


### file

***
Query SEKOIA.IO Intelligence Center for information about this indicator. No information is returned if the value is not a known by SEKOIA.IO as an indicator (IoC). STIX IDs can be resolved from SEKOIA.IO Intelligence Center application.


#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Indicator value. | Required | 


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
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example

```!file file="e1d4d2e829885b322f7e619cbfc2615f"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "e1d4d2e829885b322f7e619cbfc2615f",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "file",
        "Vendor": "SEKOIAIntelligenceCenter"
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "e1d4d2e829885b322f7e619cbfc2615f"
            },
            {
                "type": "SHA1",
                "value": "cb6dfb7d8732a74187f61db80aa9f31a29c10888"
            },
            {
                "type": "SHA256",
                "value": "8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a"
            },
            {
                "type": "SHA512",
                "value": "346c463b203b4aa72b5a6a3dee547d29aa03b85027f8dbb6ae61b4a81dd1f3c939f0e21b041124a0a070c1d82ef39820e191bc551d44bde8153df9a24e2f002b"
            }
        ],
        "MD5": "e1d4d2e829885b322f7e619cbfc2615f",
        "SHA1": "cb6dfb7d8732a74187f61db80aa9f31a29c10888",
        "SHA256": "8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a",
        "SHA512": "346c463b203b4aa72b5a6a3dee547d29aa03b85027f8dbb6ae61b4a81dd1f3c939f0e21b041124a0a070c1d82ef39820e191bc551d44bde8153df9a24e2f002b",
        "TrafficLightProtocol": "white"
    },
    "SEKOIAIntelligenceCenter": {
        "File": [
            {
                "confidence": 70,
                "created": "2022-10-07T12:50:48.417449Z",
                "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                "id": "indicator--8b789d31-6b2f-4b80-817b-dd39677c50af",
                "indicator_types": [
                    "malicious-activity"
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                        "phase_name": "installation"
                    },
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "persistence"
                    }
                ],
                "lang": "en",
                "modified": "2022-10-07T12:50:48.417463Z",
                "name": "[file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888']",
                "object_marking_refs": [
                    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                ],
                "pattern": "[file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888']",
                "pattern_type": "stix",
                "revoked": false,
                "spec_version": "2.1",
                "type": "indicator",
                "valid_from": "2022-10-07T00:00:00Z",
                "valid_until": "2023-10-03T00:00:00Z",
                "x_ic_deprecated": false,
                "x_ic_external_refs": [
                    "indicator--80b46478-9c59-414a-9c9b-4c0adcd22951"
                ],
                "x_ic_impacted_locations": [
                    "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                    "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                    "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                    "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                    "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                    "location--f16acf28-6181-4ec5-9821-712231a8c729",
                    "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                    "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                    "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                    "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                    "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                    "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                    "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                    "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                    "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                    "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                    "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                    "location--b9c12531-454c-44a9-8317-63a975993e11",
                    "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                    "location--b8664311-8c82-4606-a671-e30d95be5cee",
                    "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                    "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                    "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                    "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                    "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                    "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                    "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                    "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                    "location--ae089f9f-4570-4171-8612-59a1e3133444",
                    "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                    "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                    "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                    "location--21629cca-1177-4c52-8dd3-605372ed5600",
                    "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                    "location--264fcf56-c597-4c84-be35-87510fa704a2",
                    "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                    "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                    "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                    "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                    "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                    "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                    "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                    "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                    "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                    "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                    "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                    "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                    "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                    "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                    "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                    "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                    "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                    "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                    "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                    "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                    "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                    "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                    "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                    "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                    "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                    "location--339d05db-907d-49a3-b699-de004149adb7",
                    "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                    "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                    "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                    "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                    "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                    "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                    "location--984a1714-1dcb-42f8-b200-471850effa1d",
                    "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                    "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                    "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                    "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                    "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                    "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                    "location--092a468b-54e1-4199-9737-7268c84115bd",
                    "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                    "location--9966148d-0992-4f36-a617-db3f73e178aa",
                    "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                    "location--3930b337-d8ed-4854-8832-da8cb412e150",
                    "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                    "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                    "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                    "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                    "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                    "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                    "location--c10f2499-a30d-4192-b625-8dac29801910",
                    "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                    "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                    "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                    "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                    "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                    "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                    "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                    "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                    "location--52ded424-48e2-428d-8244-150b0afc6920",
                    "location--079c1553-452c-4890-8341-1acecdcaf851",
                    "location--af554517-cec1-44a8-af43-111b92b380c7",
                    "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                    "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                    "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                    "location--387542b5-5690-489f-8420-7f68b0b9b828",
                    "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                    "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                    "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                    "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                    "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                    "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                    "location--814b1637-9888-4d42-b968-cc300e2e477e",
                    "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                    "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                    "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                    "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                    "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                    "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                    "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                    "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                    "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                    "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                    "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                    "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                    "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                    "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                    "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                    "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                    "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                    "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                    "location--a4528ad8-ccd8-4261-a110-12165800f479",
                    "location--a5013209-3177-4642-90c5-9a3884717b4e",
                    "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                    "location--58797005-647b-4fe7-b261-33160e292a99",
                    "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                    "location--b1111318-86ad-41be-a876-fec7c5b30c99"
                ],
                "x_ic_impacted_sectors": [
                    "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                    "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                    "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                    "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                    "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                    "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                    "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                    "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                    "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                    "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                    "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                    "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                    "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                    "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                    "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                    "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                    "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                    "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                    "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                    "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                    "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                    "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                    "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                    "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                    "identity--22c5f173-363a-4394-899d-8c2947d19507",
                    "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                    "identity--7a486419-cd78-4fcf-845d-261539b05450",
                    "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                    "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                    "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                    "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                    "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                    "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                    "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                    "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                    "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                    "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                    "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                    "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                    "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                    "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                    "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                    "identity--6a7f7fbc-5485-42e5-a9da-b3bbc8137d21",
                    "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                    "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                    "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                    "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                    "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                    "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                    "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                    "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                    "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                    "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                    "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd"
                ],
                "x_ic_is_in_flint": false,
                "x_ic_observable_types": [
                    "file"
                ],
                "x_inthreat_sources_refs": [
                    "identity--d0644ccd-4ce2-4fb2-9165-dc7860e42984"
                ]
            },
            {
                "confidence": 70,
                "created": "2022-10-07T14:56:42.435601Z",
                "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                "external_references": [
                    {
                        "description": "agenttesla sample analyzed by Hatching's sandbox",
                        "source_name": "Hatching Triage",
                        "url": "https://tria.ge/221007-mstsvscdcq"
                    }
                ],
                "id": "indicator--b050b27a-0a60-4fd5-a1ff-4cfdf7d90ead",
                "indicator_types": [
                    "malicious-activity"
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution"
                    }
                ],
                "lang": "en",
                "modified": "2022-10-07T14:56:42.435621Z",
                "name": "[file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888' OR file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.'SHA-512' = '346c463b203b4aa72b5a6a3dee547d29aa03b85027f8dbb6ae61b4a81dd1f3c939f0e21b041124a0a070c1d82ef39820e191bc551d44bde8153df9a24e2f002b']",
                "object_marking_refs": [
                    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                ],
                "pattern": "[file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888' OR file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.'SHA-512' = '346c463b203b4aa72b5a6a3dee547d29aa03b85027f8dbb6ae61b4a81dd1f3c939f0e21b041124a0a070c1d82ef39820e191bc551d44bde8153df9a24e2f002b']",
                "pattern_type": "stix",
                "revoked": false,
                "spec_version": "2.1",
                "type": "indicator",
                "valid_from": "2022-10-07T00:00:00Z",
                "valid_until": "2025-10-08T00:00:00Z",
                "x_ic_deprecated": false,
                "x_ic_external_refs": [
                    "indicator--7059366c-6b78-4e2a-b914-2c7bf19567e0"
                ],
                "x_ic_impacted_locations": [
                    "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                    "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                    "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                    "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                    "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                    "location--f16acf28-6181-4ec5-9821-712231a8c729",
                    "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                    "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                    "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                    "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                    "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                    "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                    "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                    "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                    "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                    "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                    "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                    "location--b9c12531-454c-44a9-8317-63a975993e11",
                    "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                    "location--b8664311-8c82-4606-a671-e30d95be5cee",
                    "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                    "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                    "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                    "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                    "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                    "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                    "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                    "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                    "location--ae089f9f-4570-4171-8612-59a1e3133444",
                    "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                    "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                    "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                    "location--21629cca-1177-4c52-8dd3-605372ed5600",
                    "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                    "location--264fcf56-c597-4c84-be35-87510fa704a2",
                    "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                    "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                    "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                    "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                    "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                    "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                    "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                    "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                    "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                    "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                    "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                    "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                    "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                    "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                    "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                    "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                    "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                    "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                    "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                    "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                    "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                    "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                    "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                    "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                    "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                    "location--339d05db-907d-49a3-b699-de004149adb7",
                    "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                    "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                    "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                    "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                    "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                    "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                    "location--984a1714-1dcb-42f8-b200-471850effa1d",
                    "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                    "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                    "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                    "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                    "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                    "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                    "location--092a468b-54e1-4199-9737-7268c84115bd",
                    "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                    "location--9966148d-0992-4f36-a617-db3f73e178aa",
                    "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                    "location--3930b337-d8ed-4854-8832-da8cb412e150",
                    "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                    "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                    "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                    "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                    "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                    "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                    "location--c10f2499-a30d-4192-b625-8dac29801910",
                    "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                    "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                    "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                    "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                    "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                    "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                    "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                    "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                    "location--52ded424-48e2-428d-8244-150b0afc6920",
                    "location--079c1553-452c-4890-8341-1acecdcaf851",
                    "location--af554517-cec1-44a8-af43-111b92b380c7",
                    "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                    "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                    "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                    "location--387542b5-5690-489f-8420-7f68b0b9b828",
                    "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                    "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                    "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                    "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                    "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                    "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                    "location--814b1637-9888-4d42-b968-cc300e2e477e",
                    "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                    "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                    "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                    "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                    "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                    "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                    "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                    "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                    "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                    "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                    "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                    "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                    "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                    "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                    "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                    "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                    "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                    "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                    "location--a4528ad8-ccd8-4261-a110-12165800f479",
                    "location--a5013209-3177-4642-90c5-9a3884717b4e",
                    "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                    "location--58797005-647b-4fe7-b261-33160e292a99",
                    "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                    "location--b1111318-86ad-41be-a876-fec7c5b30c99"
                ],
                "x_ic_impacted_sectors": [
                    "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                    "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                    "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                    "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                    "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                    "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                    "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                    "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                    "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                    "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                    "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                    "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                    "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                    "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                    "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                    "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                    "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                    "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                    "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                    "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                    "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                    "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                    "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                    "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                    "identity--22c5f173-363a-4394-899d-8c2947d19507",
                    "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                    "identity--7a486419-cd78-4fcf-845d-261539b05450",
                    "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                    "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                    "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                    "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                    "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                    "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                    "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                    "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                    "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                    "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                    "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                    "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                    "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                    "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                    "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                    "identity--6a7f7fbc-5485-42e5-a9da-b3bbc8137d21",
                    "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                    "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                    "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                    "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                    "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                    "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                    "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                    "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                    "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                    "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                    "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd"
                ],
                "x_ic_is_in_flint": false,
                "x_ic_observable_types": [
                    "file"
                ],
                "x_inthreat_sources_refs": [
                    "identity--8ab8e854-ae7c-4642-a986-e6e699646a43"
                ]
            }
        ],
        "IndicatorContext": {
            "indicator": {
                "type": "file",
                "value": "e1d4d2e829885b322f7e619cbfc2615f"
            },
            "items": [
                {
                    "id": "bundle--0ff0cbb5-3026-44c8-80dc-35f562c96517",
                    "objects": [
                        {
                            "confidence": 70,
                            "created": "2022-10-07T12:50:48.417449Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "indicator--8b789d31-6b2f-4b80-817b-dd39677c50af",
                            "indicator_types": [
                                "malicious-activity"
                            ],
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "installation"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "persistence"
                                }
                            ],
                            "lang": "en",
                            "modified": "2022-10-07T12:50:48.417463Z",
                            "name": "[file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888']",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "pattern": "[file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888']",
                            "pattern_type": "stix",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "indicator",
                            "valid_from": "2022-10-07T00:00:00Z",
                            "valid_until": "2023-10-03T00:00:00Z",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "indicator--80b46478-9c59-414a-9c9b-4c0adcd22951"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--6a7f7fbc-5485-42e5-a9da-b3bbc8137d21",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_ic_observable_types": [
                                "file"
                            ],
                            "x_inthreat_sources_refs": [
                                "identity--d0644ccd-4ce2-4fb2-9165-dc7860e42984"
                            ]
                        },
                        {
                            "aliases": [
                                "Agent Tesla",
                                "AgentTesla",
                                "AgenTesla",
                                "Negasteal"
                            ],
                            "capabilities": [
                                "anti-debugging",
                                "anti-sandbox",
                                "anti-vm",
                                "captures-input-peripherals",
                                "captures-output-peripherals",
                                "communicates-with-c2",
                                "degrades-security-software",
                                "exfiltrates-data",
                                "fingerprints-host",
                                "steals-authentication-credentials"
                            ],
                            "confidence": 90,
                            "created": "2019-07-19T15:25:33.745282Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "# Resume\n\nAgent Tesla is a spyware that steals passwords and collects information about the actions of its victims by recording keystrokes and user interactions. The malware can be used by attackers to spy on victims, allowing them to see everything that has been typed in supported programs and web-browsers. The spyware has been observed in the world since 2014 and has become extremely popular in the cybercriminal community in recent years.\n\n# Chain of infection\n\nThe most widespread delivery method for Agent Tesla is malicious spam, via Microsoft Word documents that contain an embedded executed file or exploit. The email accounts used to spread the spyware are often legitimate accounts that have been compromised. Agent Tesla operators act out of opportunism and lack the sophistication seen in elaborate operations such as big game hunting.\n\nOnce the user has clicked on the malicious document, the executable is downloaded and renamed. The downloaded file runs itself and creates a child process. Before taking actions on objectives, Agent Tesla checks the environment of the compromised machine to avoid being deployed in a Virtual Machine and therefore bypass sandbox analysis. Multiple sandbox evasion techniques are performed - such as reading hardware parameters, disabling AMSI scans, checking for user input or using sleeping functions.\n\nAgent Tesla establishes persistence by creating a registry RUN key to run at boot, or creating a scheduled task via schtasks.exe. Once well installed, the malware takes actions on objectives and sends data to the Command & Control server. Latest Agent Tesla versions offer different means of communication - over SMTP, FTP or HTTP, but also using Telegram, Discord or Tor network.\nAccording to SEKOIA research, most Agent Tesla operators employ SMTP communications on port 587 using compromised email accounts.\n\n# Capacity\n\n* Taking fingerprint:\nFor example, it corresponds to the footprint of an infected machine:\n```\nTime: 02/11/2021 08:45:53\nUser Name: JohnDoe\nComputer Name: ACME-JOHN-DOE-PC\nOSFullName: Microsoft Windows 7 \u00c9dition Int\u00e9grale\nCPU: Intel(R) Core(TM)2 Duo CPU E8400 @ 3.00GHz\nRAM: 3931,59 MB\nIP Address:\n```\nIn some cases, Agent Tesla requests `api.ipify[.]org`, a simple public IP address API, to retrieve the victim IP address.\nThe body of each email sent to C2 begins with the fingerprint.\n\n* Stealing password (from many applications):\nThose information are sent by email whose subject is `PW_JohnDoe/ACME-JOHN-DOE-PC`, `PW` for password.\n\n* Keystroke logging:\nThe subject of the email is `KL_JohnDoe/ACME-JOHN-DOE-PC`, `KL` for Keystroke logging.\n\n* Stealing cookies:\nAgent Tesla archives the directories that store the cookies of different browsers, e.g.: `C:\\Users\\JohnDoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default`, and adds it as attachment to emails whose subject is `CO_JohnDoe/ACME-JOHN-DOE-PC`, `CO` for Cookies.\n\n* Capturing clipboard:\nScreenshots are taken by the spyware and sent by email whose subject is `SC_JohnDoe/ACME-JOHN-DOE-PC`, `SC` for SCreenshot.\n\nOther capabilities are available, but are less used.",
                            "external_references": [
                                {
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/software/S0331"
                                },
                                {
                                    "description": "(Citation: Fortinet Agent Tesla April 2018)(Citation: Talos Agent Tesla Oct 2018)(Citation: DigiTrust Agent Tesla Jan 2017)",
                                    "source_name": "Agent Tesla"
                                },
                                {
                                    "description": "Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.",
                                    "source_name": "Fortinet Agent Tesla April 2018",
                                    "url": "https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html"
                                },
                                {
                                    "description": "Arsene, L. (2020, April 21). Oil & Gas Spearphishing Campaigns Drop Agent Tesla Spyware in Advance of Historic OPEC+ Deal. Retrieved May 19, 2020.",
                                    "source_name": "Bitdefender Agent Tesla April 2020",
                                    "url": "https://labs.bitdefender.com/2020/04/oil-gas-spearphishing-campaigns-drop-agent-tesla-spyware-in-advance-of-historic-opec-deal/"
                                },
                                {
                                    "description": "Jazi, H. (2020, April 16). New AgentTesla variant steals WiFi credentials. Retrieved May 19, 2020.",
                                    "source_name": "Malwarebytes Agent Tesla April 2020",
                                    "url": "https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/"
                                },
                                {
                                    "description": "Brumaghin, E., et al. (2018, October 15). Old dog, new tricks - Analysing new RTF-based campaign distributing Agent Tesla, Loki with PyREbox. Retrieved November 5, 2018.",
                                    "source_name": "Talos Agent Tesla Oct 2018",
                                    "url": "https://blog.talosintelligence.com/2018/10/old-dog-new-tricks-analysing-new-rtf_15.html"
                                },
                                {
                                    "description": "The DigiTrust Group. (2017, January 12). The Rise of Agent Tesla. Retrieved November 5, 2018.",
                                    "source_name": "DigiTrust Agent Tesla Jan 2017",
                                    "url": "https://www.digitrustgroup.com/agent-tesla-keylogger/"
                                },
                                {
                                    "description": "New Agent Tesla variant discovered that is loaded from a pastebin service \u201chastebin.com\u201d which hadn\u2019t been seen in use by prominent malware families in the past.",
                                    "source_name": "The Hasty Agent: Agent Tesla Attack Uses Hastebin",
                                    "url": "https://www.deepinstinct.com/2020/10/29/the-hasty-agent-agent-tesla-attack-uses-hastebin/"
                                },
                                {
                                    "description": "A powerful, easy-to-use password stealing program known as Agent Tesla has been infecting computers since 2014, but recently this malware strain has seen a surge in popularity \u2014 attracting more than 6,300 customers who pay subscription fees to license the software",
                                    "source_name": "Who Is Agent Tesla?",
                                    "url": "https://krebsonsecurity.com/2018/10/who-is-agent-tesla/"
                                },
                                {
                                    "description": "",
                                    "source_name": "Agent Tesla",
                                    "url": "https://any.run/malware-trends/agenttesla"
                                },
                                {
                                    "description": "",
                                    "source_name": " SWEED: Exposing years of Agent Tesla campaigns ",
                                    "url": "https://blog.talosintelligence.com/2019/07/sweed-agent-tesla.html"
                                },
                                {
                                    "description": "",
                                    "source_name": "Agent Tesla amps up information stealing attacks",
                                    "url": "https://news.sophos.com/en-us/2021/02/02/agent-tesla-amps-up-information-stealing-attacks/"
                                }
                            ],
                            "id": "malware--1db42657-baba-4ada-a07b-a55d21bfdb9f",
                            "implementation_languages": [
                                "c#",
                                "visual-basic"
                            ],
                            "is_family": true,
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "installation"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "execution"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "command-and-control"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "collection"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "defense-evasion"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "persistence"
                                }
                            ],
                            "labels": [
                                "malware"
                            ],
                            "lang": "en",
                            "malware_types": [
                                "spyware"
                            ],
                            "modified": "2021-12-23T19:52:16.428429Z",
                            "more_info": "[More info about Agent Tesla on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/malware--1db42657-baba-4ada-a07b-a55d21bfdb9f)",
                            "name": "Agent Tesla",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "malware",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--0cbb95b5-06d0-4e09-aabc-2c8e8e640135",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--d2dc6c8d-c463-4872-8d43-08ca4bad5110",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--23168672-6c82-491e-8da2-fb6c5721d04f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--97287f3b-07c2-4777-838b-d6cd00ebaccb",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--6a7f7fbc-5485-42e5-a9da-b3bbc8137d21",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ],
                            "x_mitre_aliases": [
                                "Agent Tesla"
                            ],
                            "x_mitre_platforms": [
                                "Windows"
                            ],
                            "x_mitre_version": "1.1"
                        },
                        {
                            "created": "2022-10-07T12:50:48.44978Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--901fa947-9e38-4038-b876-59d9e1f9dfaa",
                            "lang": "en",
                            "modified": "2022-10-07T12:50:48.449792Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "indicates",
                            "revoked": false,
                            "source_ref": "indicator--8b789d31-6b2f-4b80-817b-dd39677c50af",
                            "spec_version": "2.1",
                            "start_time": "2022-10-07T00:00:00Z",
                            "stop_time": "2023-10-03T00:00:00Z",
                            "target_ref": "malware--1db42657-baba-4ada-a07b-a55d21bfdb9f",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "relationship--d524b80b-abe9-41b5-a759-f9202c476196"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--6a7f7fbc-5485-42e5-a9da-b3bbc8137d21",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--d0644ccd-4ce2-4fb2-9165-dc7860e42984"
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
                            "confidence": 70,
                            "contact_information": "https://bazaar.abuse.ch/",
                            "created": "2020-10-08T14:44:35.287618Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "MalwareBazaar is a project from abuse.ch with the goal of sharing malware samples with the infosec community, AV vendors and threat intelligence providers.\n\nIndicators from known malware are automatically imported in Intelligence Center by playbook.",
                            "external_references": [
                                {
                                    "source_name": "bazaar.abuse.ch",
                                    "url": "https://bazaar.abuse.ch/"
                                }
                            ],
                            "id": "identity--d0644ccd-4ce2-4fb2-9165-dc7860e42984",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-04-06T14:41:14.043207Z",
                            "name": "MalwareBazaar",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
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
                },
                {
                    "id": "bundle--dd1ec5f2-0e21-4631-b6d4-620b096eedbe",
                    "objects": [
                        {
                            "confidence": 70,
                            "created": "2022-10-07T14:56:42.435601Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "external_references": [
                                {
                                    "description": "agenttesla sample analyzed by Hatching's sandbox",
                                    "source_name": "Hatching Triage",
                                    "url": "https://tria.ge/221007-mstsvscdcq"
                                }
                            ],
                            "id": "indicator--b050b27a-0a60-4fd5-a1ff-4cfdf7d90ead",
                            "indicator_types": [
                                "malicious-activity"
                            ],
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "execution"
                                }
                            ],
                            "lang": "en",
                            "modified": "2022-10-07T14:56:42.435621Z",
                            "name": "[file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888' OR file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.'SHA-512' = '346c463b203b4aa72b5a6a3dee547d29aa03b85027f8dbb6ae61b4a81dd1f3c939f0e21b041124a0a070c1d82ef39820e191bc551d44bde8153df9a24e2f002b']",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "pattern": "[file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888' OR file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.'SHA-512' = '346c463b203b4aa72b5a6a3dee547d29aa03b85027f8dbb6ae61b4a81dd1f3c939f0e21b041124a0a070c1d82ef39820e191bc551d44bde8153df9a24e2f002b']",
                            "pattern_type": "stix",
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "indicator",
                            "valid_from": "2022-10-07T00:00:00Z",
                            "valid_until": "2025-10-08T00:00:00Z",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "indicator--7059366c-6b78-4e2a-b914-2c7bf19567e0"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--6a7f7fbc-5485-42e5-a9da-b3bbc8137d21",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_ic_observable_types": [
                                "file"
                            ],
                            "x_inthreat_sources_refs": [
                                "identity--8ab8e854-ae7c-4642-a986-e6e699646a43"
                            ]
                        },
                        {
                            "aliases": [
                                "Agent Tesla",
                                "AgentTesla",
                                "AgenTesla",
                                "Negasteal"
                            ],
                            "capabilities": [
                                "anti-debugging",
                                "anti-sandbox",
                                "anti-vm",
                                "captures-input-peripherals",
                                "captures-output-peripherals",
                                "communicates-with-c2",
                                "degrades-security-software",
                                "exfiltrates-data",
                                "fingerprints-host",
                                "steals-authentication-credentials"
                            ],
                            "confidence": 90,
                            "created": "2019-07-19T15:25:33.745282Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "# Resume\n\nAgent Tesla is a spyware that steals passwords and collects information about the actions of its victims by recording keystrokes and user interactions. The malware can be used by attackers to spy on victims, allowing them to see everything that has been typed in supported programs and web-browsers. The spyware has been observed in the world since 2014 and has become extremely popular in the cybercriminal community in recent years.\n\n# Chain of infection\n\nThe most widespread delivery method for Agent Tesla is malicious spam, via Microsoft Word documents that contain an embedded executed file or exploit. The email accounts used to spread the spyware are often legitimate accounts that have been compromised. Agent Tesla operators act out of opportunism and lack the sophistication seen in elaborate operations such as big game hunting.\n\nOnce the user has clicked on the malicious document, the executable is downloaded and renamed. The downloaded file runs itself and creates a child process. Before taking actions on objectives, Agent Tesla checks the environment of the compromised machine to avoid being deployed in a Virtual Machine and therefore bypass sandbox analysis. Multiple sandbox evasion techniques are performed - such as reading hardware parameters, disabling AMSI scans, checking for user input or using sleeping functions.\n\nAgent Tesla establishes persistence by creating a registry RUN key to run at boot, or creating a scheduled task via schtasks.exe. Once well installed, the malware takes actions on objectives and sends data to the Command & Control server. Latest Agent Tesla versions offer different means of communication - over SMTP, FTP or HTTP, but also using Telegram, Discord or Tor network.\nAccording to SEKOIA research, most Agent Tesla operators employ SMTP communications on port 587 using compromised email accounts.\n\n# Capacity\n\n* Taking fingerprint:\nFor example, it corresponds to the footprint of an infected machine:\n```\nTime: 02/11/2021 08:45:53\nUser Name: JohnDoe\nComputer Name: ACME-JOHN-DOE-PC\nOSFullName: Microsoft Windows 7 \u00c9dition Int\u00e9grale\nCPU: Intel(R) Core(TM)2 Duo CPU E8400 @ 3.00GHz\nRAM: 3931,59 MB\nIP Address:\n```\nIn some cases, Agent Tesla requests `api.ipify[.]org`, a simple public IP address API, to retrieve the victim IP address.\nThe body of each email sent to C2 begins with the fingerprint.\n\n* Stealing password (from many applications):\nThose information are sent by email whose subject is `PW_JohnDoe/ACME-JOHN-DOE-PC`, `PW` for password.\n\n* Keystroke logging:\nThe subject of the email is `KL_JohnDoe/ACME-JOHN-DOE-PC`, `KL` for Keystroke logging.\n\n* Stealing cookies:\nAgent Tesla archives the directories that store the cookies of different browsers, e.g.: `C:\\Users\\JohnDoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default`, and adds it as attachment to emails whose subject is `CO_JohnDoe/ACME-JOHN-DOE-PC`, `CO` for Cookies.\n\n* Capturing clipboard:\nScreenshots are taken by the spyware and sent by email whose subject is `SC_JohnDoe/ACME-JOHN-DOE-PC`, `SC` for SCreenshot.\n\nOther capabilities are available, but are less used.",
                            "external_references": [
                                {
                                    "source_name": "mitre-attack",
                                    "url": "https://attack.mitre.org/software/S0331"
                                },
                                {
                                    "description": "(Citation: Fortinet Agent Tesla April 2018)(Citation: Talos Agent Tesla Oct 2018)(Citation: DigiTrust Agent Tesla Jan 2017)",
                                    "source_name": "Agent Tesla"
                                },
                                {
                                    "description": "Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.",
                                    "source_name": "Fortinet Agent Tesla April 2018",
                                    "url": "https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html"
                                },
                                {
                                    "description": "Arsene, L. (2020, April 21). Oil & Gas Spearphishing Campaigns Drop Agent Tesla Spyware in Advance of Historic OPEC+ Deal. Retrieved May 19, 2020.",
                                    "source_name": "Bitdefender Agent Tesla April 2020",
                                    "url": "https://labs.bitdefender.com/2020/04/oil-gas-spearphishing-campaigns-drop-agent-tesla-spyware-in-advance-of-historic-opec-deal/"
                                },
                                {
                                    "description": "Jazi, H. (2020, April 16). New AgentTesla variant steals WiFi credentials. Retrieved May 19, 2020.",
                                    "source_name": "Malwarebytes Agent Tesla April 2020",
                                    "url": "https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/"
                                },
                                {
                                    "description": "Brumaghin, E., et al. (2018, October 15). Old dog, new tricks - Analysing new RTF-based campaign distributing Agent Tesla, Loki with PyREbox. Retrieved November 5, 2018.",
                                    "source_name": "Talos Agent Tesla Oct 2018",
                                    "url": "https://blog.talosintelligence.com/2018/10/old-dog-new-tricks-analysing-new-rtf_15.html"
                                },
                                {
                                    "description": "The DigiTrust Group. (2017, January 12). The Rise of Agent Tesla. Retrieved November 5, 2018.",
                                    "source_name": "DigiTrust Agent Tesla Jan 2017",
                                    "url": "https://www.digitrustgroup.com/agent-tesla-keylogger/"
                                },
                                {
                                    "description": "New Agent Tesla variant discovered that is loaded from a pastebin service \u201chastebin.com\u201d which hadn\u2019t been seen in use by prominent malware families in the past.",
                                    "source_name": "The Hasty Agent: Agent Tesla Attack Uses Hastebin",
                                    "url": "https://www.deepinstinct.com/2020/10/29/the-hasty-agent-agent-tesla-attack-uses-hastebin/"
                                },
                                {
                                    "description": "A powerful, easy-to-use password stealing program known as Agent Tesla has been infecting computers since 2014, but recently this malware strain has seen a surge in popularity \u2014 attracting more than 6,300 customers who pay subscription fees to license the software",
                                    "source_name": "Who Is Agent Tesla?",
                                    "url": "https://krebsonsecurity.com/2018/10/who-is-agent-tesla/"
                                },
                                {
                                    "description": "",
                                    "source_name": "Agent Tesla",
                                    "url": "https://any.run/malware-trends/agenttesla"
                                },
                                {
                                    "description": "",
                                    "source_name": " SWEED: Exposing years of Agent Tesla campaigns ",
                                    "url": "https://blog.talosintelligence.com/2019/07/sweed-agent-tesla.html"
                                },
                                {
                                    "description": "",
                                    "source_name": "Agent Tesla amps up information stealing attacks",
                                    "url": "https://news.sophos.com/en-us/2021/02/02/agent-tesla-amps-up-information-stealing-attacks/"
                                }
                            ],
                            "id": "malware--1db42657-baba-4ada-a07b-a55d21bfdb9f",
                            "implementation_languages": [
                                "c#",
                                "visual-basic"
                            ],
                            "is_family": true,
                            "kill_chain_phases": [
                                {
                                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                    "phase_name": "installation"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "execution"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "command-and-control"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "collection"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "defense-evasion"
                                },
                                {
                                    "kill_chain_name": "mitre-attack",
                                    "phase_name": "persistence"
                                }
                            ],
                            "labels": [
                                "malware"
                            ],
                            "lang": "en",
                            "malware_types": [
                                "spyware"
                            ],
                            "modified": "2021-12-23T19:52:16.428429Z",
                            "more_info": "[More info about Agent Tesla on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/malware--1db42657-baba-4ada-a07b-a55d21bfdb9f)",
                            "name": "Agent Tesla",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "malware",
                            "x_ic_deprecated": false,
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--0cbb95b5-06d0-4e09-aabc-2c8e8e640135",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--d2dc6c8d-c463-4872-8d43-08ca4bad5110",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--23168672-6c82-491e-8da2-fb6c5721d04f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--97287f3b-07c2-4777-838b-d6cd00ebaccb",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--6a7f7fbc-5485-42e5-a9da-b3bbc8137d21",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd"
                            ],
                            "x_ic_is_in_flint": true,
                            "x_inthreat_sources_refs": [
                                "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
                            ],
                            "x_mitre_aliases": [
                                "Agent Tesla"
                            ],
                            "x_mitre_platforms": [
                                "Windows"
                            ],
                            "x_mitre_version": "1.1"
                        },
                        {
                            "created": "2022-10-07T14:56:50.820388Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "id": "relationship--de3f2faa-1ec1-48ec-85e8-7d1dae7ecd10",
                            "lang": "en",
                            "modified": "2022-10-07T14:56:50.8204Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "indicates",
                            "revoked": false,
                            "source_ref": "indicator--b050b27a-0a60-4fd5-a1ff-4cfdf7d90ead",
                            "spec_version": "2.1",
                            "start_time": "2022-10-07T00:00:00Z",
                            "stop_time": "2025-10-08T00:00:00Z",
                            "target_ref": "malware--1db42657-baba-4ada-a07b-a55d21bfdb9f",
                            "type": "relationship",
                            "x_ic_deprecated": false,
                            "x_ic_external_refs": [
                                "relationship--251af4ba-3d88-4866-8a1c-aa9ba28b95db"
                            ],
                            "x_ic_impacted_locations": [
                                "location--fcdc64b6-5791-4bb2-855d-15a414ce072f",
                                "location--fb80e71b-2394-4344-a406-2ac98f0879f5",
                                "location--fa9995b1-2f58-4ed1-83d0-89ae5e491a63",
                                "location--f714e66f-f5f7-4ba2-8568-9f9e0811427d",
                                "location--f2e5b076-45a1-4c4b-ae30-95f9970cee90",
                                "location--f16acf28-6181-4ec5-9821-712231a8c729",
                                "location--ebd6f624-6ccb-429f-874d-dd4a343e0cef",
                                "location--e9be5f61-2d42-4eb6-a158-13b1547c0045",
                                "location--ddb9ac7a-8a0b-4790-a215-cb2e160d85a8",
                                "location--da6c710a-eeb8-411a-9875-7524c63f5f94",
                                "location--d6e38bb4-9e11-443f-b4f1-dc53068e15c4",
                                "location--ce895300-199f-44fc-b6ad-f69ee6305ef8",
                                "location--c2a15f03-dfc1-4659-a553-87770d75657d",
                                "location--c23c9f9d-b72f-48d2-ad74-efa16c5135a1",
                                "location--c1aceada-c5b5-40a6-9e19-5f01625f068a",
                                "location--bbe350e1-6547-410b-8cce-5f91bc8c5068",
                                "location--bbb8e2cd-a40e-4006-b315-abef26f81f41",
                                "location--b9c12531-454c-44a9-8317-63a975993e11",
                                "location--e9d38dd8-20b2-4e26-892a-9cb46bdc4d41",
                                "location--b8664311-8c82-4606-a671-e30d95be5cee",
                                "location--b6bd8dc3-d34b-49d6-8d7b-c205abca41a0",
                                "location--01a7bf2a-4bee-42bd-aac5-9f2b277ccd55",
                                "location--b2f21856-d558-4904-bbe7-f832af1adc2a",
                                "location--dea6cc03-a488-48cf-b09b-7e9ca7ad9f7c",
                                "location--3bcb58ef-94e4-47c1-92d1-65e439c50e3f",
                                "location--c58b9cf6-a29e-440c-ae3b-a3b842f5adbb",
                                "location--7e9f431f-b99e-4f34-aa19-089aad3815ee",
                                "location--bc9b90c5-be7b-483b-9e7f-15f4e4cbbbe3",
                                "location--ae089f9f-4570-4171-8612-59a1e3133444",
                                "location--4fcd8a70-7293-4681-bd72-255edc13c738",
                                "location--dbebe2ba-c3c9-415a-91ef-2d9a0c83ce87",
                                "location--4aac7d2a-42b8-4ff0-9cd2-081b500b0a2b",
                                "location--21629cca-1177-4c52-8dd3-605372ed5600",
                                "location--4390a589-27ad-497c-84bf-2a876bea06e2",
                                "location--264fcf56-c597-4c84-be35-87510fa704a2",
                                "location--3d56edf2-7a65-4c70-bcc6-f98864d1dee5",
                                "location--3b8aada1-50a8-4a50-aa00-f7bc5aca5259",
                                "location--5b52b395-79f9-4a75-b072-c8eb7be402da",
                                "location--21c1247d-4234-48cf-86a6-b24b89cab7bd",
                                "location--f73feb6e-5d1a-4ee8-9bc9-9a53c69928cb",
                                "location--62decb69-71ae-49d3-8a1b-0189d78cad69",
                                "location--66e9febd-33ca-4736-aec5-a9d9e13a6345",
                                "location--35553bf8-64ae-4c3a-bc8c-ec4fffd65ed7",
                                "location--0c074b83-cfe7-4b1d-bd11-18bbe0c39609",
                                "location--867d31af-0ae0-4738-ba86-6353a0e5fb01",
                                "location--34a19294-45f8-4664-9ea8-263002fe81d2",
                                "location--c41ef74a-4292-47df-95f5-6f8ef7d2efb8",
                                "location--b749a012-362f-43a0-aff7-171f9a0bedbc",
                                "location--7aa2d1f9-0fb1-4181-8d4b-1b4d12858c30",
                                "location--3423cede-cd5d-4878-a30b-a5cfe1b33096",
                                "location--1175a3bd-dd53-4a7e-9cdd-50743079025a",
                                "location--75614c0c-d8ea-4eb6-ab97-2d473da06f96",
                                "location--7027490f-ab4d-4a66-ab41-5639a3ef666f",
                                "location--8c5bf53a-8409-45c1-9d17-36e9df9355b1",
                                "location--59fb0b50-8792-4ad7-abd1-c5b67311a315",
                                "location--01d5f74a-2417-4c8e-a799-4eda69ac64d0",
                                "location--10687ab6-8f6f-48c0-bd76-b1f0ad5502cc",
                                "location--69336d60-ce82-41b3-99c9-d73493a1a15e",
                                "location--0363042f-05b9-42d7-b47e-7b9d04696bc2",
                                "location--9671f7eb-5b14-485e-befd-6fc3bdb38366",
                                "location--339d05db-907d-49a3-b699-de004149adb7",
                                "location--457d7ea7-6965-463e-b739-f83912eda8f5",
                                "location--10fbf417-71ad-4d61-a6c4-8ad40033432a",
                                "location--62bb8e3e-7919-48e0-9608-c7569388d2c3",
                                "location--1b39de90-a068-43da-9cdf-689aff1a1da1",
                                "location--94f39acc-2999-4dcd-9f43-012d4f315f4b",
                                "location--968ec102-a99f-4c94-85d0-f1a52227bd60",
                                "location--984a1714-1dcb-42f8-b200-471850effa1d",
                                "location--f5006be8-5dc6-489a-914a-4ba656f2df3e",
                                "location--05eae806-132b-4ce9-a307-5352c2b27d51",
                                "location--9e0b858a-2715-4d8e-b937-53707c48710f",
                                "location--9f5eaaa6-bf4d-4371-b411-4c6da9f1fa98",
                                "location--369e8445-c3b9-49f3-8dc8-a8df793513f0",
                                "location--a5e214d3-3584-4a96-ba86-e4f9bb07d148",
                                "location--092a468b-54e1-4199-9737-7268c84115bd",
                                "location--4f5c2d10-5a9a-4c6e-b75e-216c74f365ba",
                                "location--9966148d-0992-4f36-a617-db3f73e178aa",
                                "location--150d4cad-d2fb-4344-af03-c5d8cdc10116",
                                "location--3930b337-d8ed-4854-8832-da8cb412e150",
                                "location--7efb98bd-8f7f-4a4e-9ca4-44f382705ce5",
                                "location--48636655-0643-488d-b4f0-dfb68a96cb8d",
                                "location--9cdd3dae-449f-4111-a59a-779c88bf3099",
                                "location--9d6b38f0-30ae-4ca3-b36d-79bd418ff382",
                                "location--5b5cd168-59c8-45a0-ae61-8bdc7873b88c",
                                "location--a4e3db4d-364f-4407-bb63-8e15028cc3aa",
                                "location--c10f2499-a30d-4192-b625-8dac29801910",
                                "location--03289a2f-a7af-475c-89b5-d071fcd80277",
                                "location--32682647-80fa-47ca-a364-8b8ab337d4ef",
                                "location--ffa8eb57-0736-475a-ad11-623bb5a99fff",
                                "location--53aabc6d-a513-4659-a82d-f064c2054cb1",
                                "location--60c65af5-26b6-4a74-a785-45388295b7d3",
                                "location--a06b3afd-e04c-4aaf-a8a2-b984ccbc8753",
                                "location--1719933e-1ce5-43f6-ac2f-e9318b194235",
                                "location--1e3ce2dd-6fb6-40a2-8dd2-d2310c64f5f0",
                                "location--52ded424-48e2-428d-8244-150b0afc6920",
                                "location--079c1553-452c-4890-8341-1acecdcaf851",
                                "location--af554517-cec1-44a8-af43-111b92b380c7",
                                "location--66eb84d8-04ae-41f4-b4b7-3557aa8fd5a3",
                                "location--68750320-c937-4395-8f4f-29d5ea7e028f",
                                "location--6d02aae4-38b9-499b-9dea-d6818886ef8e",
                                "location--387542b5-5690-489f-8420-7f68b0b9b828",
                                "location--6ddedc37-60ae-48b9-afc9-96b640382165",
                                "location--e54570c2-da38-4424-82f3-df8a89587c2b",
                                "location--41e6f61f-d388-4317-b583-3d508b1d7776",
                                "location--750b17e5-c1a0-4ef9-88ec-e0b6851d18f0",
                                "location--d81eecc8-fc8e-4bed-8c28-25e79b5d2ba6",
                                "location--79ead060-7b84-4a4a-a4cc-9eed380dd798",
                                "location--814b1637-9888-4d42-b968-cc300e2e477e",
                                "location--82b6e924-7bd8-4e19-9685-6863196fc60f",
                                "location--c828b4b2-7847-4b03-8bc7-13f528df6099",
                                "location--86a2a4c9-c5f4-4106-a64c-960c0d2d5e17",
                                "location--8b65ff3b-2caf-4c96-a384-235b1bb2feda",
                                "location--a7f5c36c-8808-4b22-b2f4-fa65ad00b1bc",
                                "location--dcf747a4-f013-4f5c-924d-7226335e09f9",
                                "location--8bb25232-5e69-4cd3-8991-9dab7abb25ff",
                                "location--17a894ea-dbb4-403d-baa7-bbd7d93aa97e",
                                "location--171d89d4-9b71-4a81-b47f-e75fd62df4fb",
                                "location--97a9a8ca-47f2-4015-9bcd-c87d87d2a8a1",
                                "location--2f1865d4-5f10-4a06-a45c-c6c8a3e5d053",
                                "location--97ccd734-9ab2-4022-8809-fea8e8b4b7fd",
                                "location--98d8b0e0-9d65-4019-a0f1-f9b435adc5d5",
                                "location--27444b14-8e5b-45ba-8665-cab7ea46a70e",
                                "location--9d781941-4a8b-4b52-86b5-4162057c91f4",
                                "location--9de733a6-1fed-4254-8aa5-c6c1262e8615",
                                "location--99225dd7-8311-4a2e-8d82-4859aed0f48b",
                                "location--9ef79c7e-473a-444b-95e1-8285b80aa28e",
                                "location--a4528ad8-ccd8-4261-a110-12165800f479",
                                "location--a5013209-3177-4642-90c5-9a3884717b4e",
                                "location--a678bc81-d40c-4455-9242-501de8cd0b02",
                                "location--58797005-647b-4fe7-b261-33160e292a99",
                                "location--a047aae7-4090-4d7e-af51-52b5979c545f",
                                "location--b1111318-86ad-41be-a876-fec7c5b30c99"
                            ],
                            "x_ic_impacted_sectors": [
                                "identity--f910fbcc-9f6a-43db-a6da-980c224ab2dd",
                                "identity--f56e1adb-86d2-46a8-89f9-544ed0d8f6e2",
                                "identity--ec9d3a40-064c-4ec0-b678-85f5623fc4f1",
                                "identity--499a1938-8f6f-4023-82a1-56400e42d697",
                                "identity--47ce715f-5c62-4991-8862-19efbb0a8dee",
                                "identity--3dc8d72a-ce30-4846-af7b-431d1a4f9fd1",
                                "identity--3a6e8c1b-db90-4f81-a677-a57d0ee7f055",
                                "identity--3384b397-24c7-4935-8d33-e4970aa11298",
                                "identity--39746349-9c5c-47bd-8f39-0aff658d8ee7",
                                "identity--337c119c-6436-4bd8-80a5-dcec9bad3b2d",
                                "identity--333fecdb-e60d-46e4-9f21-5424dccef693",
                                "identity--0ecc1054-756c-47d5-b7d2-640e5ba96513",
                                "identity--0f39d60f-f703-45e7-ace0-1fbbb583fb2c",
                                "identity--cac0be1b-803d-4c41-aaa9-c9179f2aaff4",
                                "identity--f29d78a1-dea7-4a86-af74-79fa19410907",
                                "identity--3067ae6a-56f4-43b6-8cdf-3c41f8f5799f",
                                "identity--d3ccd9b0-9961-475e-8899-43c41d20cce1",
                                "identity--dde50644-38ad-414a-bb6e-e097123558b5",
                                "identity--0429cd5f-7adc-48eb-9eac-461e86e6ec54",
                                "identity--197fc617-c50c-421a-a73f-cb0cfedfe51f",
                                "identity--5b6a9899-d0cd-4e09-8e73-4a60f88b8547",
                                "identity--04ca1d36-bfd3-4150-860c-16fa85d14c6d",
                                "identity--1c2ca424-60ca-4dfa-91e8-5231ae86f4e6",
                                "identity--86488fc3-2973-4e62-b230-f6441f7d39f0",
                                "identity--22c5f173-363a-4394-899d-8c2947d19507",
                                "identity--0e2aa4de-d09e-4a77-9669-ec699af62089",
                                "identity--7a486419-cd78-4fcf-845d-261539b05450",
                                "identity--9aa7cd5f-9abb-44e9-9a39-fc559ab94158",
                                "identity--39729d0f-a13b-4b24-abbe-0912a135aee7",
                                "identity--b34cbcb2-4adc-4291-9909-21df1e40eec1",
                                "identity--d4ee4ce4-0b99-4316-a00f-08afeeb68586",
                                "identity--91ef3906-6821-4fa9-a75b-af7bf57da8c6",
                                "identity--26f07f1b-1596-41c1-b23b-8efc5b105792",
                                "identity--de6d2cda-d23b-47b5-a869-1065044aefe0",
                                "identity--99b2746a-3ece-422c-aa6e-833fbc28ebd5",
                                "identity--53779867-8f50-4e4b-afab-88fbbc6aa508",
                                "identity--275946eb-0b8a-4ffc-9297-56f2275ef0d2",
                                "identity--063ef3d7-3989-4cf6-95ee-6217c0ab367a",
                                "identity--62b911a8-bcab-4f31-91f0-af9cdf9b6d20",
                                "identity--ecc48a52-4495-4f19-bc26-5ee51c176816",
                                "identity--98bc4ec8-590f-49bf-b51e-b37228b6a4c0",
                                "identity--b5fcb38e-7e4c-436c-b443-2f5f8e522a53",
                                "identity--6a7f7fbc-5485-42e5-a9da-b3bbc8137d21",
                                "identity--41070ab8-3181-4c01-9f75-c11df5fb1ca3",
                                "identity--b683566b-e6f0-406f-867a-3c3541cca886",
                                "identity--7c5012dc-75c8-43e7-bf89-a3feb28e48b4",
                                "identity--8e1db464-79dd-44d5-bc20-6b305d879674",
                                "identity--b48266ac-b1b8-4d85-bf09-a56dd0462a14",
                                "identity--c1371a50-ab86-4ddc-8a0f-2021be3dae63",
                                "identity--db4a2f1a-9480-4dc7-92f5-88aafd6f83ba",
                                "identity--c38472aa-9b41-471f-9110-2d1ff51b39f0",
                                "identity--c42b7875-6d1f-4415-8b66-e998cb4355fb",
                                "identity--ce0be931-0e2e-4e07-864c-b9b169da5f15",
                                "identity--d8dfac5a-7d94-480e-abcc-c0a303bf26cd"
                            ],
                            "x_ic_is_in_flint": false,
                            "x_inthreat_sources_refs": [
                                "identity--8ab8e854-ae7c-4642-a986-e6e699646a43"
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
                            "confidence": 70,
                            "created": "2021-03-25T13:14:50.530309Z",
                            "created_by_ref": "identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
                            "description": "Hatching Triage is providing sandbox to its users, one big feature provided is automated extraction of malware configurations.\n\nAll malware configurations and hashes from existing extractors  are imported automatically to Intelligence Center.",
                            "external_references": [
                                {
                                    "source_name": "tria.ge",
                                    "url": "https://tria.ge/"
                                }
                            ],
                            "id": "identity--8ab8e854-ae7c-4642-a986-e6e699646a43",
                            "identity_class": "organization",
                            "lang": "en",
                            "modified": "2022-04-06T14:31:16.553777Z",
                            "name": "tria.ge",
                            "object_marking_refs": [
                                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                            ],
                            "revoked": false,
                            "spec_version": "2.1",
                            "type": "identity",
                            "x_ic_deprecated": false,
                            "x_ic_is_in_flint": false,
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

>### Indicator [file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888'] is linked to the following:

>|name|description|type|aliases|goals|revoked|created|modified|more_info|
>|---|---|---|---|---|---|---|---|---|
>| Agent Tesla | # Resume<br/><br/>Agent Tesla is a spyware that steals passwords and collects information about the actions of its victims by recording keystrokes and user interactions. The malware can be used by attackers to spy on victims, allowing them to see everything that has been typed in supported programs and web-browsers. The spyware has been observed in the world since 2014 and has become extremely popular in the cybercriminal community in recent years.<br/><br/># Chain of infection<br/><br/>The most widespread delivery method for Agent Tesla is malicious spam, via Microsoft Word documents that contain an embedded executed file or exploit. The email accounts used to spread the spyware are often legitimate accounts that have been compromised. Agent Tesla operators act out of opportunism and lack the sophistication seen in elaborate operations such as big game hunting.<br/><br/>Once the user has clicked on the malicious document, the executable is downloaded and renamed. The downloaded file runs itself and creates a child process. Before taking actions on objectives, Agent Tesla checks the environment of the compromised machine to avoid being deployed in a Virtual Machine and therefore bypass sandbox analysis. Multiple sandbox evasion techniques are performed - such as reading hardware parameters, disabling AMSI scans, checking for user input or using sleeping functions.<br/><br/>Agent Tesla establishes persistence by creating a registry RUN key to run at boot, or creating a scheduled task via schtasks.exe. Once well installed, the malware takes actions on objectives and sends data to the Command & Control server. Latest Agent Tesla versions offer different means of communication - over SMTP, FTP or HTTP, but also using Telegram, Discord or Tor network.<br/>According to SEKOIA research, most Agent Tesla operators employ SMTP communications on port 587 using compromised email accounts.<br/><br/># Capacity<br/><br/>* Taking fingerprint:<br/>For example, it corresponds to the footprint of an infected machine:<br/>\`\`\`<br/>Time: 02/11/2021 08:45:53<br/>User Name: JohnDoe<br/>Computer Name: ACME-JOHN-DOE-PC<br/>OSFullName: Microsoft Windows 7 Édition Intégrale<br/>CPU: Intel(R) Core(TM)2 Duo CPU E8400 @ 3.00GHz<br/>RAM: 3931,59 MB<br/>IP Address:<br/>\`\`\`<br/>In some cases, Agent Tesla requests \`api.ipify[.]org\`, a simple public IP address API, to retrieve the victim IP address.<br/>The body of each email sent to C2 begins with the fingerprint.<br/><br/>* Stealing password (from many applications):<br/>Those information are sent by email whose subject is \`PW_JohnDoe/ACME-JOHN-DOE-PC\`, \`PW\` for password.<br/><br/>* Keystroke logging:<br/>The subject of the email is \`KL_JohnDoe/ACME-JOHN-DOE-PC\`, \`KL\` for Keystroke logging.<br/><br/>* Stealing cookies:<br/>Agent Tesla archives the directories that store the cookies of different browsers, e.g.: \`C:\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\`, and adds it as attachment to emails whose subject is \`CO_JohnDoe/ACME-JOHN-DOE-PC\`, \`CO\` for Cookies.<br/><br/>* Capturing clipboard:<br/>Screenshots are taken by the spyware and sent by email whose subject is \`SC_JohnDoe/ACME-JOHN-DOE-PC\`, \`SC\` for SCreenshot.<br/><br/>Other capabilities are available, but are less used. | malware | Agent Tesla,<br/>AgentTesla,<br/>AgenTesla,<br/>Negasteal |  | false | 2019-07-19T15:25:33.745282Z | 2021-12-23T19:52:16.428429Z | [More info about Agent Tesla on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/malware--1db42657-baba-4ada-a07b-a55d21bfdb9f) |

>### Indicator [file:hashes.MD5 = 'e1d4d2e829885b322f7e619cbfc2615f' OR file:hashes.'SHA-1' = 'cb6dfb7d8732a74187f61db80aa9f31a29c10888' OR file:hashes.'SHA-256' = '8fdc11e44341c3df5a8020b3313eb0a33b2d77fa05d4af0168f911b3a4d3b74a' OR file:hashes.'SHA-512' = '346c463b203b4aa72b5a6a3dee547d29aa03b85027f8dbb6ae61b4a81dd1f3c939f0e21b041124a0a070c1d82ef39820e191bc551d44bde8153df9a24e2f002b'] is linked to the following:

>|name|description|type|aliases|goals|revoked|created|modified|more_info|
>|---|---|---|---|---|---|---|---|---|
>| Agent Tesla | # Resume<br/><br/>Agent Tesla is a spyware that steals passwords and collects information about the actions of its victims by recording keystrokes and user interactions. The malware can be used by attackers to spy on victims, allowing them to see everything that has been typed in supported programs and web-browsers. The spyware has been observed in the world since 2014 and has become extremely popular in the cybercriminal community in recent years.<br/><br/># Chain of infection<br/><br/>The most widespread delivery method for Agent Tesla is malicious spam, via Microsoft Word documents that contain an embedded executed file or exploit. The email accounts used to spread the spyware are often legitimate accounts that have been compromised. Agent Tesla operators act out of opportunism and lack the sophistication seen in elaborate operations such as big game hunting.<br/><br/>Once the user has clicked on the malicious document, the executable is downloaded and renamed. The downloaded file runs itself and creates a child process. Before taking actions on objectives, Agent Tesla checks the environment of the compromised machine to avoid being deployed in a Virtual Machine and therefore bypass sandbox analysis. Multiple sandbox evasion techniques are performed - such as reading hardware parameters, disabling AMSI scans, checking for user input or using sleeping functions.<br/><br/>Agent Tesla establishes persistence by creating a registry RUN key to run at boot, or creating a scheduled task via schtasks.exe. Once well installed, the malware takes actions on objectives and sends data to the Command & Control server. Latest Agent Tesla versions offer different means of communication - over SMTP, FTP or HTTP, but also using Telegram, Discord or Tor network.<br/>According to SEKOIA research, most Agent Tesla operators employ SMTP communications on port 587 using compromised email accounts.<br/><br/># Capacity<br/><br/>* Taking fingerprint:<br/>For example, it corresponds to the footprint of an infected machine:<br/>\`\`\`<br/>Time: 02/11/2021 08:45:53<br/>User Name: JohnDoe<br/>Computer Name: ACME-JOHN-DOE-PC<br/>OSFullName: Microsoft Windows 7 Édition Intégrale<br/>CPU: Intel(R) Core(TM)2 Duo CPU E8400 @ 3.00GHz<br/>RAM: 3931,59 MB<br/>IP Address:<br/>\`\`\`<br/>In some cases, Agent Tesla requests \`api.ipify[.]org\`, a simple public IP address API, to retrieve the victim IP address.<br/>The body of each email sent to C2 begins with the fingerprint.<br/><br/>* Stealing password (from many applications):<br/>Those information are sent by email whose subject is \`PW_JohnDoe/ACME-JOHN-DOE-PC\`, \`PW\` for password.<br/><br/>* Keystroke logging:<br/>The subject of the email is \`KL_JohnDoe/ACME-JOHN-DOE-PC\`, \`KL\` for Keystroke logging.<br/><br/>* Stealing cookies:<br/>Agent Tesla archives the directories that store the cookies of different browsers, e.g.: \`C:\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\`, and adds it as attachment to emails whose subject is \`CO_JohnDoe/ACME-JOHN-DOE-PC\`, \`CO\` for Cookies.<br/><br/>* Capturing clipboard:<br/>Screenshots are taken by the spyware and sent by email whose subject is \`SC_JohnDoe/ACME-JOHN-DOE-PC\`, \`SC\` for SCreenshot.<br/><br/>Other capabilities are available, but are less used. | malware | Agent Tesla,<br/>AgentTesla,<br/>AgenTesla,<br/>Negasteal |  | false | 2019-07-19T15:25:33.745282Z | 2021-12-23T19:52:16.428429Z | [More info about Agent Tesla on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/malware--1db42657-baba-4ada-a07b-a55d21bfdb9f) |


### email

***
Query SEKOIA.IO Intelligence Center for information about this indicator. No information is returned if the value is not a known by SEKOIA.IO as an indicator (IoC). STIX IDs can be resolved from SEKOIA.IO Intelligence Center application.


#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Indicator value. | Required | 


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
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example

```!email email="eicar@sekoia.io"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "eicar@sekoia.io",
        "Reliability": "F - Reliability cannot be judged",
        "Score": 1,
        "Type": "email",
        "Vendor": "SEKOIAIntelligenceCenter"
    },
    "Email": {
        "Address": "eicar@sekoia.io",
        "Domain": "sekoia.io",
        "TrafficLightProtocol": "green"
    },
    "SEKOIAIntelligenceCenter": {
        "EMAIL": {
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
        "IndicatorContext": {
            "indicator": {
                "type": "email-addr",
                "value": "eicar@sekoia.io"
            },
            "items": [
                {
                    "id": "bundle--673a174f-2b86-4bce-b381-331a43855d49",
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
>| EICAR Unit of SEKOIA | This Intrusion Set is known to be operated by SEKOIA by its EICAR unit. This unit aims at creating fictitious environment mimicking real attackers to present how threat intelligence can help real organizations to protect themselves.<br/> | intrusion-set | EICAR,<br/>TEST EICAR SEKOIA.IO,<br/>EICAR Unit of SEKOIA | Simulation of real Threat Actor for Test purpose | false | 2020-05-26T13:18:26.429787Z | 2020-06-02T13:28:51.131904Z | [More info about EICAR Unit of SEKOIA on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/intrusion-set--4d1fd514-d9a4-45f3-988a-d811df72df2f) |


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
| URL.Data | String | The URL | 
| Domain.Name | String | The domain name, for example: "google.com". | 
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
    "DBotScore": {
        "Indicator": "eicar@sekoia.io",
        "Reliability": "F - Reliability cannot be judged",
        "Score": 1,
        "Type": "email",
        "Vendor": "SEKOIAIntelligenceCenter"
    },
    "Email": {
        "Address": "eicar@sekoia.io",
        "Domain": "sekoia.io",
        "TrafficLightProtocol": "green"
    },
    "SEKOIAIntelligenceCenter": {
        "EMAIL": {
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
        "IndicatorContext": {
            "indicator": {
                "type": "email-addr",
                "value": "eicar@sekoia.io"
            },
            "items": [
                {
                    "id": "bundle--95c7a6bd-39db-4e9b-8e33-81d57713dcaa",
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
>| EICAR Unit of SEKOIA | This Intrusion Set is known to be operated by SEKOIA by its EICAR unit. This unit aims at creating fictitious environment mimicking real attackers to present how threat intelligence can help real organizations to protect themselves.<br/> | intrusion-set | EICAR,<br/>TEST EICAR SEKOIA.IO,<br/>EICAR Unit of SEKOIA | Simulation of real Threat Actor for Test purpose | false | 2020-05-26T13:18:26.429787Z | 2020-06-02T13:28:51.131904Z | [More info about EICAR Unit of SEKOIA on SEKOIA.IO](https://app.sekoia.io/intelligence/objects/intrusion-set--4d1fd514-d9a4-45f3-988a-d811df72df2f) |
