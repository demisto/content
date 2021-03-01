Ingest indicator feeds from OpenCTI. Works with OpenCTI v4 instances. For v3 OpenCTI version OpenCTI Feed v3 integration should be used.
This integration was integrated and tested with version v4.0.7 of OpenCTI Feed v4
## Configure OpenCTI Feed v4 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpenCTI Feed v4.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL |  | True |
    | API Key |  | True |
    | Indicators Type to fetch | The indicator types to fetch. Out of the box indicator types supported in XSOAR are: "Account", "Domain", "Email", "File", "Host", "IP", "IPv6", "Registry Key", and "URL". The rest will not cause automatic indicator creation in XSOAR. The default is "ALL". | True |
    | Max. indicators per fetch |  | False |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Tags | Supports CSV values. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### opencti-get-indicators
***
Gets indicators from the feed.


#### Base Command

`opencti-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return per fetch. The default value is "50". Maximum value is "500". | Optional | 
| indicator_types | The indicator types to fetch. Out of the box indicator types supported in XSOAR are: "Account", "Domain", "Email", "File", "Host", "IP", "IPv6", "Registry Key", and "URL". The rest will not cause automatic indicator creation in XSOAR. The default is "ALL". Possible values are: ALL, Account, Domain, Email, File, Host, IP, IPv6, Registry Key, URL. Default is ALL. | Optional | 
| last_run_id | The last ID from the previous call from which to begin pagination for this call. You can find this value at OpenCTI.IndicatorsList.LastRunID context path. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicators.IndicatorsList.type | String | Indicator type. | 
| OpenCTI.Indicators.IndicatorsList.value | String | Indicator value. | 
| OpenCTI.Indicators.IndicatorsList.id | String | Indicator id. | 
| OpenCTI.Indicators.IndicatorsList.rawJSON.createdBy | Unknown | The creator of indicator. | 
| OpenCTI.Indicators.IndicatorsList.rawJSON.score | Number | Indicator score. | 
| OpenCTI.Indicators.IndicatorsList.rawJSON.description | String | Indicator Description. | 
| OpenCTI.Indicators.IndicatorsList.rawJSON.objectLabel | Unknown | Indicator labels. | 
| OpenCTI.Indicators.IndicatorsList.rawJSON.objectMarking | Unknown | Indicator marking definitions. | 
| OpenCTI.Indicators.IndicatorsList.rawJSON.externalReferences | Unknown | Indicator external references. | 
| OpenCTI.Indicators.LastRunID | String | the id of the last fetch to use pagination. | 


#### Command Example
```!opencti-get-indicators limit=2 indicator_types="IP"```

#### Context Example
```json
{
    "OpenCTI": {
        "Indicators": {
            "IndicatorsList": [
                {
                    "id": "33bd535b-fa1c-41e2-a6f9-80d82dd29a9b",
                    "rawJSON": {
                        "createdBy": {
                            "contact_information": null,
                            "created": "2021-02-14T11:57:57.259Z",
                            "description": "test playbook organization",
                            "entity_type": "Organization",
                            "id": "1e12fe87-db3e-4838-8391-6910547bf60d",
                            "modified": "2021-02-14T11:57:57.259Z",
                            "name": "Test_Organization",
                            "objectLabel": [],
                            "objectLabelIds": [],
                            "parent_types": [
                                "Basic-Object",
                                "Stix-Object",
                                "Stix-Core-Object",
                                "Stix-Domain-Object",
                                "Identity"
                            ],
                            "roles": null,
                            "spec_version": "2.1",
                            "standard_id": "identity--b3d82735-562e-5641-add7-1b45adf8fba2",
                            "x_opencti_aliases": null,
                            "x_opencti_organization_type": null,
                            "x_opencti_reliability": "B"
                        },
                        "createdById": "1e12fe87-db3e-4838-8391-6910547bf60d",
                        "created_at": "2021-02-18T08:04:10.997Z",
                        "entity_type": "IPv4-Addr",
                        "externalReferences": [],
                        "externalReferencesIds": [],
                        "id": "33bd535b-fa1c-41e2-a6f9-80d82dd29a9b",
                        "indicators": [],
                        "indicatorsIds": [],
                        "objectLabel": [
                            {
                                "color": "#7ed321",
                                "createdById": null,
                                "id": "fa57f98e-f2f5-45fd-97f2-bf2c53119044",
                                "value": "devdemisto"
                            },
                            {
                                "color": "#5d0d8a",
                                "createdById": null,
                                "id": "07cfae2d-6cc9-42c5-9fd0-32eff8142404",
                                "value": "test-label-1"
                            }
                        ],
                        "objectLabelIds": [
                            "fa57f98e-f2f5-45fd-97f2-bf2c53119044",
                            "07cfae2d-6cc9-42c5-9fd0-32eff8142404"
                        ],
                        "objectMarking": [
                            {
                                "created": "2021-01-26T11:31:07.317Z",
                                "createdById": null,
                                "definition": "TLP:RED",
                                "definition_type": "TLP",
                                "entity_type": "Marking-Definition",
                                "id": "c9819001-c80c-45e1-8edb-e543e350f195",
                                "modified": "2021-01-26T11:31:07.317Z",
                                "standard_id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
                                "x_opencti_color": "#c62828",
                                "x_opencti_order": 4
                            }
                        ],
                        "objectMarkingIds": [
                            "c9819001-c80c-45e1-8edb-e543e350f195"
                        ],
                        "observable_value": "1.1.1.1",
                        "parent_types": [
                            "Basic-Object",
                            "Stix-Object",
                            "Stix-Core-Object",
                            "Stix-Cyber-Observable"
                        ],
                        "spec_version": "2.1",
                        "standard_id": "ipv4-addr--1d5586d0-4327-5e1c-9317-19c1e0cf8ec0",
                        "updated_at": "2021-02-18T08:04:10.997Z",
                        "value": "1.1.1.1",
                        "x_opencti_description": "test fetch one",
                        "x_opencti_score": 100
                    },
                    "type": "IP",
                    "value": "1.1.1.1"
                },
                {
                    "id": "700c8187-2dce-4aeb-bf3a-0864cb7b02c7",
                    "rawJSON": {
                        "createdBy": {
                            "contact_information": null,
                            "created": "2021-02-14T11:57:57.259Z",
                            "description": "test playbook organization",
                            "entity_type": "Organization",
                            "id": "1e12fe87-db3e-4838-8391-6910547bf60d",
                            "modified": "2021-02-14T11:57:57.259Z",
                            "name": "Test_Organization",
                            "objectLabel": [],
                            "objectLabelIds": [],
                            "parent_types": [
                                "Basic-Object",
                                "Stix-Object",
                                "Stix-Core-Object",
                                "Stix-Domain-Object",
                                "Identity"
                            ],
                            "roles": null,
                            "spec_version": "2.1",
                            "standard_id": "identity--b3d82735-562e-5641-add7-1b45adf8fba2",
                            "x_opencti_aliases": null,
                            "x_opencti_organization_type": null,
                            "x_opencti_reliability": "B"
                        },
                        "createdById": "1e12fe87-db3e-4838-8391-6910547bf60d",
                        "created_at": "2021-02-22T08:45:48.778Z",
                        "entity_type": "IPv4-Addr",
                        "externalReferences": [],
                        "externalReferencesIds": [],
                        "id": "700c8187-2dce-4aeb-bf3a-0864cb7b02c7",
                        "indicators": [],
                        "indicatorsIds": [],
                        "objectLabel": [
                            {
                                "color": "#7ed321",
                                "createdById": null,
                                "id": "fa57f98e-f2f5-45fd-97f2-bf2c53119044",
                                "value": "devdemisto"
                            }
                        ],
                        "objectLabelIds": [
                            "fa57f98e-f2f5-45fd-97f2-bf2c53119044"
                        ],
                        "objectMarking": [
                            {
                                "created": "2021-01-26T11:31:07.238Z",
                                "createdById": null,
                                "definition": "TLP:AMBER",
                                "definition_type": "TLP",
                                "entity_type": "Marking-Definition",
                                "id": "9128e411-c759-4af0-aeb0-b65f12082648",
                                "modified": "2021-01-26T11:31:07.238Z",
                                "standard_id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                                "x_opencti_color": "#d84315",
                                "x_opencti_order": 3
                            }
                        ],
                        "objectMarkingIds": [
                            "9128e411-c759-4af0-aeb0-b65f12082648"
                        ],
                        "observable_value": "1.2.3.4",
                        "parent_types": [
                            "Basic-Object",
                            "Stix-Object",
                            "Stix-Core-Object",
                            "Stix-Cyber-Observable"
                        ],
                        "spec_version": "2.1",
                        "standard_id": "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
                        "updated_at": "2021-02-22T08:45:48.778Z",
                        "value": "1.2.3.4",
                        "x_opencti_description": "test_desc",
                        "x_opencti_score": 70
                    },
                    "type": "IP",
                    "value": "1.2.3.4"
                }
            ],
            "lastRunID": "YXJyYXljb25uZWN0aW9uOjI="
        }
    }
}
```

#### Human Readable Output

>### Indicators
>|type|value|id|
>|---|---|---|
>| IP | 1.1.1.1 | 33bd535b-fa1c-41e2-a6f9-80d82dd29a9b |
>| IP | 1.2.3.4 | 700c8187-2dce-4aeb-bf3a-0864cb7b02c7 |


### opencti-indicator-delete
***
Delete indicator.


#### Base Command

`opencti-indicator-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-indicator-delete id=20cb3239-9165-4b24-a16a-b1083524980b```

#### Human Readable Output

>Indicator deleted.

### opencti-indicator-field-update
***
Update indicator field. Available fields to update - score, description.


#### Base Command

`opencti-indicator-field-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required | 
| field | Indicator field to update. Possible values are: score, description. | Required | 
| value | Value of the field to update. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicator.id | String | Updated indicator id. | 


#### Command Example
```!opencti-indicator-field-update field=score id=81d63245-9ba3-495d-8e78-03b037d71e01 value=100```

#### Context Example
```json
{
    "OpenCTI": {
        "Indicator": {
            "id": "81d63245-9ba3-495d-8e78-03b037d71e01"
        }
    }
}
```

#### Human Readable Output

>Indicator 81d63245-9ba3-495d-8e78-03b037d71e01 updated successfully.

### opencti-indicator-create
***
Create new indicator.


#### Base Command

`opencti-indicator-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The indicator type to create. Out of the box indicator types supported in XSOAR are: "Account", "Domain", "Email", "File-md5", "File-sha1", "File-sha256", "Host", "IP", "IPV6", "Registry Key", and "URL". The rest will not cause automatic indicator creation in XSOAR. Possible values are: Account, Domain, Email, File-MD5, File-SHA1, File-SHA256, Host, IP, IPv6, Registry Key, URL. | Required | 
| created_by | Organization id. Use opencti-organization-list to find all organizations id at opencti, or use opencti-organization-create to create new organization id. | Optional | 
| marking_id | Indicator marking id. Use opencti-marking-definition-list to find all marking definitions id at opencti. | Optional | 
| label_id | Indicator label id. Use opencti-label-list to find all labels id at opencti, or use opencti-label-create to create new label. | Optional | 
| external_references_id | External References URL. Use opencti-external-reference-create to create new external reference. | Optional | 
| description | Indicator description. | Optional | 
| score | Indicator score - number between 0 - 100. Default score value 50. | Optional | 
| data | Indicator data - json. Mandatory Data fields are: value - value of the indicator, mandatory for the following types: Domain, Email, IP, IPV6-Addr, URL, Host. For file-md5, file-sha1, file-sha256 data argument should contain hash. For Account type data should contain account_login. Registry Key data json should contain key "key". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicator.id | String | New indicator id. | 
| OpenCTI.Indicator.data | Unknown | New indicator data. | 


#### Command Example
```!opencti-indicator-create type=Domain created_by=0c7cb378-64c3-4809-b423-986ac7cecf91 description=test data="{\"value\": \"TestDomainDocs.com\"}" score=70 label_id=fa57f98e-f2f5-45fd-97f2-bf2c53119044 marking_id=9128e411-c759-4af0-aeb0-b65f12082648```

#### Context Example
```json
{
    "OpenCTI": {
        "Indicator": {
            "data": {
                "type": "Domain-Name",
                "value": "TestDomainDocs.com"
            },
            "id": "7ed5946a-81a2-4490-8be8-06d3633a41fb"
        }
    }
}
```

#### Human Readable Output

>Indicator created successfully. New Indicator id: 7ed5946a-81a2-4490-8be8-06d3633a41fb

### opencti-indicator-field-add
***
Add field to indicator. Avalible fields to add - marking defenition, label.


#### Base Command

`opencti-indicator-field-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required | 
| field | Indicator field to add. Possible values are: marking, label. | Required | 
| value | Value of the field to add. Enter label id or marking id. Use opencti-label-list to find all labels id at opencti, or use opencti-label-create to create new label. Use opencti-marking-definition-list to find all marking definitions id at opencti. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-indicator-field-add id=33bd535b-fa1c-41e2-a6f9-80d82dd29a9b field=label value=07cfae2d-6cc9-42c5-9fd0-32eff8142404```

#### Human Readable Output

>Added label successfully.

### opencti-indicator-field-remove
***
Remove field from indicator. Avalible fields to remove - marking defenition, label.


#### Base Command

`opencti-indicator-field-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required | 
| field | Indicator field to update. Possible values are: marking, label. | Required | 
| value | Value of the field to remove. Enter label id or marking id. Use opencti-label-list to find all labels id at opencti or opencti-marking-definition-list to find all marking definitions id at opencti. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-indicator-field-remove id=33bd535b-fa1c-41e2-a6f9-80d82dd29a9b field=marking value=c9819001-c80c-45e1-8edb-e543e350f195```

#### Human Readable Output

>marking: c9819001-c80c-45e1-8edb-e543e350f195 was removed successfully from indicator: 33bd535b-fa1c-41e2-a6f9-80d82dd29a9b.

### opencti-organization-list
***
Get list of all organizations.


#### Base Command

`opencti-organization-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of organizations to return per fetch. The default value is "50". Maximum value is "200". Default is 50. | Optional | 
| last_run_id | The last ID from the previous call from which to begin pagination for this call. You can find this value at OpenCTI.Organizations.organizationsLastRun context path. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Organizations.OrganizationsList.id | String | Organization id. | 
| OpenCTI.Organizations.OrganizationsList.name | String | Organization name. | 
| OpenCTI.Organizations.organizationsLastRun | String | the id of the last fetch to use pagination. | 


#### Command Example
```!opencti-organization-list limit=2```

#### Context Example
```json
{
    "OpenCTI": {
        "Organizations": {
            "OrganizationsList": [
                {
                    "id": "1e12fe87-db3e-4838-8391-6910547bf60d",
                    "name": "Test_Organization"
                },
                {
                    "id": "11ddff08-8933-46d7-ab22-31f49496499f",
                    "name": "ExampleOrganization"
                }
            ],
            "organizationsLastRun": "YXJyYXljb25uZWN0aW9uOjI="
        }
    }
}
```

#### Human Readable Output

>### Organizations
>|Name|Id|
>|---|---|
>| Test_Organization | 1e12fe87-db3e-4838-8391-6910547bf60d |
>| ExampleOrganization | 11ddff08-8933-46d7-ab22-31f49496499f |


### opencti-organization-create
***
Create organization.


#### Base Command

`opencti-organization-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of organization to create. | Required | 
| description | Description of the organization. | Optional | 
| reliability | Reliability of the organization. Possible values are: A, B, C, D, E, F. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Organization.id | String | New organization id. | 


#### Command Example
```!opencti-organization-create name=ExampleOrganization description="create organization" reliability="C"```

#### Context Example
```json
{
    "OpenCTI": {
        "Organization": {
            "id": "11ddff08-8933-46d7-ab22-31f49496499f"
        }
    }
}
```

#### Human Readable Output

>Organization ExampleOrganization was created successfully with id: 11ddff08-8933-46d7-ab22-31f49496499f.

### opencti-reset-fetch-indicators
***
WARNING: This command will reset your fetch history.


#### Base Command

`opencti-reset-fetch-indicators`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-reset-fetch-indicators```

#### Human Readable Output

>Fetch history deleted successfully

### opencti-label-list
***
Get list of all labels.


#### Base Command

`opencti-label-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of labels to return per fetch. The default value is "50". Default is 50. | Optional | 
| last_run_id | The last ID from the previous call from which to begin pagination for this call. You can find this value at OpenCTI.Labels.labelsLastRun context path. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Labels.LabelsList.id | String | Label id. | 
| OpenCTI.Labels.LabelsList.value | String | Label name. | 
| OpenCTI.Labels.labelsLastRun | String | the id of the last fetch to use pagination. | 


#### Command Example
```!opencti-label-list limit=2```

#### Context Example
```json
{
    "OpenCTI": {
        "Labels": [
            {
                "LabelsList": [
                    {
                        "id": "7ba41668-1594-4a09-9be5-3640f2c2d253",
                        "value": "demisto_lablel"
                    },
                    {
                        "id": "fa57f98e-f2f5-45fd-97f2-bf2c53119044",
                        "value": "devdemisto"
                    }
                ]
            },
            {
                "labelsLastRun": "YXJyYXljb25uZWN0aW9uOjI="
            }
        ]
    }
}
```

#### Human Readable Output

>### Labels
>|Value|Id|
>|---|---|
>| demisto_lablel | 7ba41668-1594-4a09-9be5-3640f2c2d253 |
>| devdemisto | fa57f98e-f2f5-45fd-97f2-bf2c53119044 |


### opencti-label-create
***
Create label.


#### Base Command

`opencti-label-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of label to create. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Label.id | String | New label id. | 


#### Command Example
```!opencti-label-create name=docsTest```

#### Context Example
```json
{
    "OpenCTI": {
        "Label": {
            "id": "beb5159a-e162-4352-b7d7-6e355db7f057"
        }
    }
}
```

#### Human Readable Output

>Label docsTest was created successfully with id: beb5159a-e162-4352-b7d7-6e355db7f057.

### opencti-external-reference-create
***
Create external reference.


#### Base Command

`opencti-external-reference-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | External References URL. | Required | 
| source_name | External References Source Name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.externalReference.id | String | New external reference id. | 


#### Command Example
```!opencti-external-reference-create source_name=source_name url=www.url.com```

#### Context Example
```json
{
    "OpenCTI": {
        "externalReference": {
            "id": "8339d023-ada2-4b32-8a29-0a3897fc096d"
        }
    }
}
```

#### Human Readable Output

>Reference source_name was created successfully with id: 8339d023-ada2-4b32-8a29-0a3897fc096d.

### opencti-marking-definition-list
***
Get list of all marking definitions.


#### Base Command

`opencti-marking-definition-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of marking definitions to return per fetch. The default value is "50". Default is 50. | Optional | 
| last_run_id | The last ID from the previous call from which to begin pagination for this call. You can find this value at OpenCTI.MarkingDefinitions.markingsLastRun context path. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.MarkingDefinitions.MarkingDefinitionsList.id | String | Label id. | 
| OpenCTI.MarkingDefinitions.MarkingDefinitionsList.value | String | Label name. | 
| OpenCTI.MarkingDefinitions.markingsLastRun | String | the id of the last fetch to use pagination. | 


#### Command Example
```!opencti-marking-definition-list limit=2```

#### Context Example
```json
{
    "OpenCTI": {
        "MarkingDefinitions": {
            "MarkingDefinitionsList": [
                {
                    "id": "dc911977-796a-4d96-95e4-615bd1c41263",
                    "value": "TLP:GREEN"
                },
                {
                    "id": "9128e411-c759-4af0-aeb0-b65f12082648",
                    "value": "TLP:AMBER"
                }
            ],
            "markingsLastRun": "YXJyYXljb25uZWN0aW9uOjI="
        }
    }
}
```

#### Human Readable Output

>### Markings
>|Value|Id|
>|---|---|
>| TLP:GREEN | dc911977-796a-4d96-95e4-615bd1c41263 |
>| TLP:AMBER | 9128e411-c759-4af0-aeb0-b65f12082648 |

