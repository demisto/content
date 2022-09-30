Fetch Indicator and Observables from SEKOIA.IO Intelligence Center.
To use this integration, please create an API Key with the right permissions.

This integration was integrated and tested with version xx of SEKOIAIntelligenceCenter

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


### ip
***
Query SEKOIA.IO Intelligence Center for information about this indicator. No information is returned if the value is not a known by SEKOIA.IO as an indicator (IoC).


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
            "modified": "2022-09-26T15:11:59.540139Z",
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
            "valid_until": "2022-10-06T00:00:00Z",
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
                    "id": "bundle--eca1cfb0-c3e8-4d67-8c11-d10290a0111d",
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
                            "modified": "2022-09-26T15:11:59.540139Z",
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
                            "valid_until": "2022-10-06T00:00:00Z",
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
                            "modified": "2022-09-26T15:11:59.738254Z",
                            "object_marking_refs": [
                                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                            ],
                            "relationship_type": "indicates",
                            "revoked": false,
                            "source_ref": "indicator--368e5bc7-5fa2-47da-b175-2ab7222a428a",
                            "spec_version": "2.1",
                            "start_time": "2021-10-18T00:00:00Z",
                            "stop_time": "2022-10-06T00:00:00Z",
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
>| FinFisher | [FinFisher](https:<span>//</span>attack.mitre.org/software/S0182) is a government-grade commercial surveillance spyware reportedly sold exclusively to government agencies for use in targeted and lawful criminal investigations. It is heavily obfuscated and uses multiple anti-analysis techniques. It has other variants including [Wingbird](https:<span>//</span>attack.mitre.org/software/S0176). (Citation: FinFisher Citation) (Citation: Microsoft SIR Vol 21) (Citation: FireEye FinSpy Sept 2017) (Citation: Securelist BlackOasis Oct 2017) (Citation: Microsoft FinFisher March 2018) | malware | FinFisher |  | false | 2019-07-19T15:25:38.820741Z | 2021-11-23T09:13:59.891896Z | [More info about FinFisher on SEKOIA.IO](https:<span>//</span>app.sekoia.io/intelligence/objects/malware--a36a2045-61dd-4462-8d5a-95d6732b74c3) |


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
    "SEKOIAIntelligenceCenter": {
        "IndicatorContext": {
            "indicator": {
                "type": "email-addr",
                "value": "eicar@sekoia.io"
            },
            "items": [
                {
                    "id": "bundle--6616d859-059b-410e-8915-b66e534617d8",
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

