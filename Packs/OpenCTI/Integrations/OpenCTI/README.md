Manages observables from OpenCTI.  
This integration was tested with version 5.12.17 of OpenCTI.  

## Configure OpenCTI in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Base URL | True |
| API Key (leave empty. Fill in the API key in the password field.) | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### opencti-get-observables

***
Gets observables from OpenCTI.


#### Base Command

`opencti-get-observables`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of observables to return. Default value is 50. Maximum value is 500. | Optional | 
| score_start | Score minimum value to filter by. Values range is 0-100. | Optional | 
| score_end | Score maximum value to filter by. Values range is 0-100.| Optional | 
| observable_types | The observable types to fetch. Out-of-the-box observable types supported in XSOAR are: Account, Domain, Email, File, Host, IP, IPv6, Registry Key, and URL. Possible values are: ALL, Account, Domain, Email, File, Host, IP, IPv6, Registry Key, URL. Default is ALL. | Optional | 
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.ObservablesList.LastRunID context path. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Observables.ObservablesList.type | String | Observable type. | 
| OpenCTI.Observables.ObservablesList.value | String | Observable value. | 
| OpenCTI.Observables.ObservablesList.id | String | Observable ID. | 
| OpenCTI.Observables.ObservablesList.createdBy | Unknown | The creator of the observable. | 
| OpenCTI.Observables.ObservablesList.score | Number | Observable score. | 
| OpenCTI.Observables.ObservablesList.description | String | Observable description. | 
| OpenCTI.Observables.ObservablesList.labels | Unknown | Observable labels. | 
| OpenCTI.Observables.ObservablesList.marking | Unknown | Observable marking definitions. | 
| OpenCTI.Observables.ObservablesList.externalReferences | Unknown | Observable external references. | 
| OpenCTI.Observables.LastRunID | String | The last ID of the previous fetch to use for pagination. | 


#### Command Example

```!opencti-get-observables score_start=20 score_end=70 observable_types=Domain```

#### Context Example

```json
{
    "OpenCTI": {
        "Observables": {
            "ObservablesList": [
                {
                    "createdBy": "0c7cb378-64c3-4809-b423-986ac7cecf91",
                    "description": "test",
                    "externalReferences": [],
                    "id": "7ed5946a-81a2-4490-8be8-06d3633a41fb",
                    "labels": [
                        "devdemisto"
                    ],
                    "marking": [
                        "TLP:AMBER"
                    ],
                    "score": 70,
                    "type": "Domain",
                    "value": "TestDomainDocs.com"
                },
                {
                    "createdBy": null,
                    "description": null,
                    "externalReferences": [],
                    "id": "ebe37223-f455-4122-b83d-3cfb8d8784ea",
                    "labels": [],
                    "marking": [
                        "TLP:AMBER"
                    ],
                    "score": 50,
                    "type": "Domain",
                    "value": "test1111"
                },
                {
                    "createdBy": null,
                    "description": "sdfghjk",
                    "externalReferences": [
                        {
                            "created": "2021-02-09T14:50:39.587Z",
                            "createdById": null,
                            "description": null,
                            "entity_type": "External-Reference",
                            "external_id": null,
                            "hash": null,
                            "id": "c42f673d-b2fa-40df-8ae3-c5cb25626663",
                            "modified": "2021-02-09T14:50:39.587Z",
                            "source_name": "source test",
                            "standard_id": "external-reference--e1b0cc44-a5bd-5729-9d1f-765b0d8e59e7",
                            "url": "www.test.com"
                        },
                        {
                            "created": "2021-02-22T09:37:46.634Z",
                            "createdById": null,
                            "description": null,
                            "entity_type": "External-Reference",
                            "external_id": null,
                            "hash": null,
                            "id": "a46acbf0-9996-400e-bc5d-f756c48f52c1",
                            "modified": "2021-02-22T09:37:46.634Z",
                            "source_name": "TestPlaybook",
                            "standard_id": "external-reference--be9a7896-80c0-5ec9-80e7-fd072c1808c9",
                            "url": "www.testplaybook.com"
                        },
                        {
                            "created": "2021-02-21T15:06:39.147Z",
                            "createdById": null,
                            "description": null,
                            "entity_type": "External-Reference",
                            "external_id": null,
                            "hash": null,
                            "id": "62ae7aec-e9e4-4c2a-b789-dfe6c213d391",
                            "modified": "2021-02-21T15:06:39.147Z",
                            "source_name": "name_test",
                            "standard_id": "external-reference--76fed957-9221-56db-8457-65816e4b0fdd",
                            "url": "http://test.com"
                        }
                    ],
                    "id": "74faf2e8-bbab-4a1a-a548-58db202c5e57",
                    "labels": [],
                    "marking": [
                        "TLP:WHITE"
                    ],
                    "score": 50,
                    "type": "Domain",
                    "value": "xcvbnm"
                }
            ],
            "lastRunID": "YXJyYXljb25uZWN0aW9uOjM="
        }
    }
}
```

#### Human Readable Output

>### Observables

>|type|value|id|
>|---|---|---|
>| Domain | TestDomainDocs.com | 7ed5946a-81a2-4490-8be8-06d3633a41fb |
>| Domain | test1111 | ebe37223-f455-4122-b83d-3cfb8d8784ea |
>| Domain | xcvbnm | 74faf2e8-bbab-4a1a-a548-58db202c5e57 |


### opencti-observable-delete

***
Delete observable.


#### Base Command

`opencti-observable-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Observable ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example

```!opencti-observable-delete id=74faf2e8-bbab-4a1a-a548-58db202c5e57```

#### Human Readable Output

>Observable deleted.

### opencti-observable-field-update

***
Update the observable field. The fields that can be updated are: score, description.


#### Base Command

`opencti-observable-field-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Observable ID. | Required | 
| field | Observable field to update. Possible values are: score, description. | Required | 
| value | Value of the field to update. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Observable.id | String | Updated observable ID. | 


#### Command Example

```!opencti-observable-field-update field=score id=81d63245-9ba3-495d-8e78-03b037d71e01 value=100```

#### Context Example

```json
{
    "OpenCTI": {
        "Observable": {
            "id": "81d63245-9ba3-495d-8e78-03b037d71e01"
        }
    }
}
```

#### Human Readable Output

>Observable 81d63245-9ba3-495d-8e78-03b037d71e01 updated successfully.

### opencti-observable-create

***
Create new observable.


#### Base Command

`opencti-observable-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The observable type to create. Out-of-the-box observable types supported in XSOAR are: Account, Domain, Email, File-MD5, File-SHA1, File-SHA256, Host, IP, IPV6, Registry Key, and URL. Possible values are: Account, Domain, Email, File-MD5, File-SHA1, File-SHA256, Host, IP, IPv6, Registry Key, URL. | Required | 
| created_by | Organization ID. Use opencti-organization-list to find all organization IDs in OpenCTI, or use opencti-organization-create to create a new organization ID. | Optional | 
| marking_id | Observable marking definition ID. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Optional | 
| label_id | Observable label ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. | Optional | 
| external_references_id | External references URL. Use opencti-external-reference-create to create a new external reference. | Optional | 
| description | Observable description. | Optional | 
| score | Observable score. Values range is 0 - 100. Default value is 50. | Optional | 
| value | Observable value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Observable.id | String | New observable ID. | 
| OpenCTI.Observable.value | String | New observable value. | 
| OpenCTI.Observable.type | String | New observable type. | 


#### Command Example

```!opencti-observable-create type=Domain created_by=0c7cb378-64c3-4809-b423-986ac7cecf91 description=test value="TestDomainDocs.com" score=70 label_id=fa57f98e-f2f5-45fd-97f2-bf2c53119044 marking_id=9128e411-c759-4af0-aeb0-b65f12082648```

#### Context Example

```json
{
    "OpenCTI": {
        "Observable": {
            "id": "7ed5946a-81a2-4490-8be8-06d3633a41fb",
            "type": "Domain",
            "value": "TestDomainDocs.com"
        }
    }
}
```

#### Human Readable Output

>Observable created successfully. New Observable id: 7ed5946a-81a2-4490-8be8-06d3633a41fb

### opencti-observable-field-add

***
Add a field to the observable. Fields that can be added are marking definition and label.


#### Base Command

`opencti-observable-field-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Observable ID. | Required | 
| field | Observable field to add. Possible values are: marking, label. | Required | 
| value | Value of the field to add. Enter label ID or marking definition ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example

```!opencti-observable-field-add id=33bd535b-fa1c-41e2-a6f9-80d82dd29a9b field=label value=07cfae2d-6cc9-42c5-9fd0-32eff8142404```

#### Human Readable Output

>Added label successfully.

### opencti-observable-field-remove

***
Remove observable field value. Fields which values can be removed are marking definition and label.


#### Base Command

`opencti-observable-field-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Observable ID. | Required | 
| field | Observable field to update. Possible values are: marking, label. | Required | 
| value | Value of the field to remove. Enter label ID or marking definition ID. Use opencti-label-list to find all label IDs in OpenCTI or opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example

```!opencti-observable-field-remove id=33bd535b-fa1c-41e2-a6f9-80d82dd29a9b field=marking value=c9819001-c80c-45e1-8edb-e543e350f195```

#### Human Readable Output

>marking: c9819001-c80c-45e1-8edb-e543e350f195 was removed successfully from observable: 33bd535b-fa1c-41e2-a6f9-80d82dd29a9b.

### opencti-organization-list

***
Get a list of all organizations in OpenCTI.


#### Base Command

`opencti-organization-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of organizations to return per fetch. Default value is 50. Maximum value is 200. Default is 50. | Optional | 
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.Organizations.organizationsLastRun context path. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Organizations.OrganizationsList.id | String | Organization ID. | 
| OpenCTI.Organizations.OrganizationsList.name | String | Organization name. | 
| OpenCTI.Organizations.organizationsLastRun | String | The last ID of the previous fetch to use for pagination. | 


#### Command Example

```!opencti-organization-list limit=2```

#### Context Example

```json
{
    "OpenCTI": {
        "Organizations": [
            {
                "OrganizationsList": [
                    {
                        "id": "1e12fe87-db3e-4838-8391-6910547bf60d",
                        "name": "Test_Organization"
                    },
                    {
                        "id": "11ddff08-8933-46d7-ab22-31f49496499f",
                        "name": "ExampleOrganization"
                    }
                ]
            },
            {
                "organizationsLastRun": "YXJyYXljb25uZWN0aW9uOjI="
            }
        ]
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
Create a new organization.


#### Base Command

`opencti-organization-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the organization to create. | Required | 
| description | Description of the organization. | Optional | 
| reliability | Reliability of the organization. Possible values are: A, B, C, D, E, F. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Organization.id | String | New organization ID. | 


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

### opencti-label-list

***
Get list of all labels.


#### Base Command

`opencti-label-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of labels to return per fetch. Default is 50. | Optional | 
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.Labels.labelsLastRun context path. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Labels.LabelsList.id | String | Label ID. | 
| OpenCTI.Labels.LabelsList.value | String | Label name. | 
| OpenCTI.Labels.labelsLastRun | String | The last ID of the previous fetch to use for pagination. | 


#### Command Example

```!opencti-label-list limit=2```

#### Context Example

```json
{
    "OpenCTI": {
        "Labels": {
            "LabelsList": [
                {
                    "id": "7ba41668-1594-4a09-9be5-3640f2c2d253",
                    "value": "demisto_lablel"
                },
                {
                    "id": "fa57f98e-f2f5-45fd-97f2-bf2c53119044",
                    "value": "devdemisto"
                }
            ],
            "labelsLastRun": "YXJyYXljb25uZWN0aW9uOjI="
        }
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
Create a new label.


#### Base Command

`opencti-label-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the new label to create. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Label.id | String | New label ID. | 


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
| url | External references URL. | Required | 
| source_name | External references source name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.externalReference.id | String | New external reference ID. | 


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
Get a list of all marking definitions.


#### Base Command

`opencti-marking-definition-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of marking definitions to return per fetch. Default is 50. | Optional | 
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.MarkingDefinitions.markingsLastRun context path. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.MarkingDefinitions.MarkingDefinitionsList.id | String | Marking definition ID. | 
| OpenCTI.MarkingDefinitions.MarkingDefinitionsList.value | String | Marking definition name. | 
| OpenCTI.MarkingDefinitions.markingsLastRun | String | The last ID of the previous fetch to use for pagination. | 


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
