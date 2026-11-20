Manages OpenCTI platform. Compatible with OpenCTI 6.9 and later versions.
This integration was integrated and tested with OpenCTI 6.9.0 and 7.261103.0.

## Configure OpenCTI in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | The URL of the OpenCTI platform, for example https://opencti.example.com. | True |
| API Key | The API key of the OpenCTI user, available in the API access section of the user profile in OpenCTI. | False |
| Trust any certificate (not secure) | Whether to skip the verification of the SSL certificate of the OpenCTI platform. | False |
| Use system proxy settings | Whether to use the system proxy settings to connect to the OpenCTI platform. | False |
| Redirect stdout | Used for troubleshooting purposes. | False |
| Source Reliability | The reliability of the source providing the intelligence data. | False |
| Suspicious score threshold (0-100) | Used by the ip, domain, email, url and file commands. An indicator whose OpenCTI score \(x_opencti_score\) is above this threshold and not above the malicious score threshold is suspicious. An indicator whose score is not above this threshold is good. A value unknown to OpenCTI, or whose indicators are all revoked, is unknown. | False |
| Malicious score threshold (0-100) | Used by the ip, domain, email, url and file commands. An indicator whose OpenCTI score \(x_opencti_score\) is above this threshold is malicious. Must not be below the suspicious score threshold. | False |
| Create relationships | Whether to create relationships between indicators as part of enrichment. | False |

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
| score_start | Score minimum value to filter by. Values range is 0-100. . | Optional |
| score_end | Score maximum value to filter by. Values range is 0-100. . | Optional |
| score | A specific score. Values range is 0-100 or Unknown. | Optional |
| observable_types | The observable types to fetch. Out-of-the-box observable types supported in Cortex XSOAR are: Account, Domain, Email, File, Host, IP, IPv6, Registry Key, and URL. Possible values are: ALL, Account, Domain, Email, File, Host, IP, IPv6, Registry Key, URL. Default is ALL. | Optional |
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.ObservablesList.LastRunID context path. | Optional |
| search | The observable's value to filter by. Can be a partial value. | Optional |
| additional_filters | List of filters to apply. Format: [{key: str, operator: str, values: list[str], mode: str}, ...]. | Optional |
| all_results | When the argument is set to true, the limit argument is ignored. Possible values are: true, false. Default is false. | Optional |

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

#### Command example

```!opencti-get-observables score_start=20 score_end=70 observable_types=Domain limit=2```

#### Context Example

```json
{
    "OpenCTI": {
        "Observables": [
            {
                "ObservablesList": [
                    {
                        "createdBy": "f5acfabd-a4a6-4921-8d82-a6d35c482373",
                        "description": "Simple observable of indicator {unpeoritas.art}",
                        "externalReferences": [
                            {
                                "created": "2026-07-14T07:39:01.127Z",
                                "createdById": null,
                                "description": "Google Threat Intelligence Domain Link",
                                "entity_type": "External-Reference",
                                "external_id": null,
                                "hash": null,
                                "id": "24b4fb0f-3014-47bc-a61f-5ee225a21e55",
                                "modified": "2026-07-14T07:39:01.127Z",
                                "source_name": "[GTI] Domain unpeoritas.art",
                                "standard_id": "external-reference--3b97700e-965e-5eaa-b8f5-6c450cb18587",
                                "url": "https://www.virustotal.com/gui/domain/unpeoritas.art"
                            }
                        ],
                        "id": "f41843be-2e63-4f9a-9c09-768c269b15cd",
                        "labels": null,
                        "marking": [
                            "TLP:AMBER+STRICT"
                        ],
                        "score": 25,
                        "type": "Domain",
                        "value": "unpeoritas.art"
                    },
                    {
                        "createdBy": "27d148c4-2971-4f09-95b2-1b8fb74911d3",
                        "description": "Simple observable of indicator {ewsgeuwyeqwqoagm.xyz}",
                        "externalReferences": [
                            {
                                "created": "2026-04-04T10:01:01.568Z",
                                "createdById": null,
                                "description": null,
                                "entity_type": "External-Reference",
                                "external_id": null,
                                "hash": null,
                                "id": "3c447feb-a415-42df-90f1-6eecf689f10b",
                                "modified": "2026-05-16T14:24:26.564Z",
                                "source_name": "Sekoia.io",
                                "standard_id": "external-reference--968c3b01-37b6-5113-9a8e-ee53ba4501d1",
                                "url": "https://app.sekoia.io/intelligence/objects/indicator--7c3dfa9d-2b03-4ef6-88fd-3e3c819b91d9"
                            },
                            {
                                "created": "2026-04-04T09:39:08.239Z",
                                "createdById": null,
                                "description": "metastealer sample analyzed by Hatching's sandbox",
                                "entity_type": "External-Reference",
                                "external_id": null,
                                "hash": null,
                                "id": "e5189c87-197b-4f0f-acca-096ccb9b9985",
                                "modified": "2026-05-16T08:32:26.832Z",
                                "source_name": "Hatching Triage",
                                "standard_id": "external-reference--fdfa4360-f9ee-51e2-8a12-46f184cab5b7",
                                "url": "https://tria.ge/260402-fanqkafv8w"
                            }
                        ],
                        "id": "44194f37-b684-475b-8fd0-f4aa048330fc",
                        "labels": [
                            "source:tria.ge"
                        ],
                        "marking": [
                            "TLP:CLEAR"
                        ],
                        "score": 70,
                        "type": "Domain",
                        "value": "ewsgeuwyeqwqoagm.xyz"
                    }
                ]
            },
            {
                "lastRunID": "WyJkb21haW4tbmFtZS0tMDAwMDFkODMtNzMyOC01OTExLTkyY2YtZmUzNjE5Yjk5ODQxIl0="
            }
        ]
    }
}
```

#### Human Readable Output

>### Observables
>
>|type|value|id|
>|---|---|---|
>| Domain | unpeoritas.art | f41843be-2e63-4f9a-9c09-768c269b15cd |
>| Domain | ewsgeuwyeqwqoagm.xyz | 44194f37-b684-475b-8fd0-f4aa048330fc |

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

#### Command example

```!opencti-observable-delete id=d009a630-1e8e-414b-a366-34a19387d27c```

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

#### Command example

```!opencti-observable-field-update id=c288ff0e-4601-4e97-8b21-423dc08c1f83 field=score value=80```

#### Context Example

```json
{
    "OpenCTI": {
        "Observable": {
            "id": "c288ff0e-4601-4e97-8b21-423dc08c1f83"
        }
    }
}
```

#### Human Readable Output

>Observable c288ff0e-4601-4e97-8b21-423dc08c1f83 updated successfully.

### opencti-observable-create

***
Create new observable.

#### Base Command

`opencti-observable-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The observable type to create. Out-of-the-box observable types supported in Cortex XSOAR are: Account, Domain, Email, File-MD5, File-SHA1, File-SHA256, Host, IP, IPV6, Registry Key, and URL. Possible values are: Account, Domain, Email, File-MD5, File-SHA1, File-SHA256, Host, IP, IPv6, Registry Key, URL. | Required |
| created_by | Organization ID. Use opencti-organization-list to find all organization IDs in OpenCTI, or use opencti-organization-create to create a new organization ID. | Optional |
| marking_id | Observable marking definition ID. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Optional |
| label_id | Observable label ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. | Optional |
| external_references_id | External reference ID. Use opencti-external-reference-create to create a new external reference. | Optional |
| description | Observable description. | Optional |
| score | Observable score. Values range is 0 - 100. Default value is 50. | Optional |
| value | Observable value. | Optional |
| create_indicator | Create OpenCTI indicator related with the OpenCTI observable created. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Observable.id | String | New observable ID. |
| OpenCTI.Observable.value | String | New observable value. |
| OpenCTI.Observable.type | String | New observable type. |

#### Command example

```!opencti-observable-create type=Domain created_by=b545b7c4-b7eb-42d0-a39d-7077b43c6e1f description=test value="testdomaindocs.example.com" score=70 label_id=c532efcd-70b6-4d0a-b8a3-dcd2e51a3fe6 marking_id=936174b6-df6d-4370-ae76-97b03fb438b8```

#### Context Example

```json
{
    "OpenCTI": {
        "Observable": {
            "id": "c748602a-0f86-4f03-877a-ac4a7d11cc6b",
            "type": "Domain",
            "value": "testdomaindocs.example.com"
        }
    }
}
```

#### Human Readable Output

>Observable created successfully. New Observable id: c748602a-0f86-4f03-877a-ac4a7d11cc6b

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

#### Command example

```!opencti-observable-field-add id=c288ff0e-4601-4e97-8b21-423dc08c1f83 field=label value=c532efcd-70b6-4d0a-b8a3-dcd2e51a3fe6```

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

#### Command example

```!opencti-observable-field-remove id=c288ff0e-4601-4e97-8b21-423dc08c1f83 field=marking value=936174b6-df6d-4370-ae76-97b03fb438b8```

#### Human Readable Output

>marking: 936174b6-df6d-4370-ae76-97b03fb438b8 was removed successfully from observable: c288ff0e-4601-4e97-8b21-423dc08c1f83.

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

#### Command example

```!opencti-organization-list limit=2```

#### Context Example

```json
{
    "OpenCTI": {
        "Organizations": [
            {
                "OrganizationsList": [
                    {
                        "id": "a8d8b716-180c-4d80-bb3a-5766fc1ad09b",
                        "name": "Island Networks Limited"
                    },
                    {
                        "id": "28f67bc2-7cc6-4471-8e73-187257740e2a",
                        "name": "Texas Research International"
                    }
                ]
            },
            {
                "organizationsLastRun": "WyJpZGVudGl0eS0tMDAwYzkyMzMtZTFhZi01NDgzLThhNzItNjBiZDVkY2RjMzg0Il0="
            }
        ]
    }
}
```

#### Human Readable Output

>### Organizations
>
>|Name|Id|
>|---|---|
>| Island Networks Limited | a8d8b716-180c-4d80-bb3a-5766fc1ad09b |
>| Texas Research International | 28f67bc2-7cc6-4471-8e73-187257740e2a |

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

#### Command example

```!opencti-organization-create name=ExampleOrganization description="create organization" reliability=C```

#### Context Example

```json
{
    "OpenCTI": {
        "Organization": {
            "id": "1dba249c-e294-4e5e-a882-de9cbfb51986"
        }
    }
}
```

#### Human Readable Output

>Organization ExampleOrganization was created successfully with id: 1dba249c-e294-4e5e-a882-de9cbfb51986.

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

#### Command example

```!opencti-label-list limit=2```

#### Context Example

```json
{
    "OpenCTI": {
        "Labels": {
            "LabelsList": [
                {
                    "id": "1599c3a1-ea1d-412f-9f2d-18b01b5609b9",
                    "value": "menu issues"
                },
                {
                    "id": "e907544e-bd66-4cd4-be5f-f774318835af",
                    "value": "browser-data-extraction"
                }
            ],
            "labelsLastRun": "WyJsYWJlbC0tMDAwNTc3ZTAtYjk1My01ZTJlLTg0MTMtNWYwZTI2NmY5ZDdjIl0="
        }
    }
}
```

#### Human Readable Output

>### Labels
>
>|Value|Id|
>|---|---|
>| menu issues | 1599c3a1-ea1d-412f-9f2d-18b01b5609b9 |
>| browser-data-extraction | e907544e-bd66-4cd4-be5f-f774318835af |

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

#### Command example

```!opencti-label-create name=docsTest```

#### Context Example

```json
{
    "OpenCTI": {
        "Label": {
            "id": "808dd76e-fb19-448d-83b9-007433552699"
        }
    }
}
```

#### Human Readable Output

>Label docsTest was created successfully with id: 808dd76e-fb19-448d-83b9-007433552699.

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

#### Command example

```!opencti-external-reference-create source_name=source_name url=https://www.example.com```

#### Context Example

```json
{
    "OpenCTI": {
        "externalReference": {
            "id": "c5242160-e66e-420b-80ab-07a35d9575db"
        }
    }
}
```

#### Human Readable Output

>Reference source_name was created successfully with id: c5242160-e66e-420b-80ab-07a35d9575db.

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

#### Command example

```!opencti-marking-definition-list limit=2```

#### Context Example

```json
{
    "OpenCTI": {
        "MarkingDefinitions": {
            "MarkingDefinitionsList": [
                {
                    "id": "62d7dc92-c621-4990-a212-c4518ddb285b",
                    "value": "cc-by-sa-4.0 disarm foundation"
                },
                {
                    "id": "c18f7da4-ee8d-4609-a4fd-39595c5b02e9",
                    "value": "CAPEC is sponsored by US-CERT in the office of Cybersecurity and Communications at the U.S. Department of Homeland Security. Copyright © 2007 - 2023, The MITRE Corporation. CAPEC and the CAPEC logo are trademarks of The MITRE Corporation."
                }
            ],
            "markingsLastRun": "WyJtYXJraW5nLWRlZmluaXRpb24tLTE5Zjg3ZWRhLTRkOGEtNWU4NC04ZGFlLThlODQwZTk0Y2YyZSJd"
        }
    }
}
```

#### Human Readable Output

>### Markings
>
>|Value|Id|
>|---|---|
>| cc-by-sa-4.0 disarm foundation | 62d7dc92-c621-4990-a212-c4518ddb285b |
>| CAPEC is sponsored by US-CERT in the office of Cybersecurity and Communications at the U.S. Department of Homeland Security. Copyright © 2007 - 2023, The MITRE Corporation. CAPEC and the CAPEC logo are trademarks of The MITRE Corporation. | c18f7da4-ee8d-4609-a4fd-39595c5b02e9 |

### opencti-incident-create

***
Create new incident.

#### Base Command

`opencti-incident-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Incident name. | Required |
| incident_type | Incident type name. Use opencti-incident-types-list to find all incident types in OpenCTI. | Optional |
| confidence | Incident confidence number. Values range is 0 - 100. Default value is 50. | Optional |
| severity | Incident severity. Possible values are: low, medium, high, critical. | Optional |
| description | Incident description. | Optional |
| source | Incident source. | Optional |
| objective | Incident objective. | Optional |
| created_by | Organization ID. Use opencti-organization-list to find all organization IDs in OpenCTI, or use opencti-organization-create to create a new organization ID. | Optional |
| first_seen | Incident first seen. YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| last_seen | Incident last seen. YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| label_id | Incident label ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. | Optional |
| marking_id | Observable marking definition ID. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Optional |
| external_references_id | External reference ID. Use opencti-external-reference-create to create a new external reference. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Incident.id | String | New incident ID. |

#### Command example

```!opencti-incident-create name=ExampleIncident description="create incident"```

#### Context Example

```json
{
    "OpenCTI": {
        "Incident": {
            "id": "9f7c1d09-14dd-408e-9e5a-8d5e5b207757"
        }
    }
}
```

#### Human Readable Output

>Incident created successfully. New Incident id: 9f7c1d09-14dd-408e-9e5a-8d5e5b207757.

### opencti-incident-delete

***
Delete incident.

#### Base Command

`opencti-incident-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Incident ID. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!opencti-incident-delete id=a695b219-c499-4bdf-8df5-348e9e4618b8```

#### Human Readable Output

>Incident deleted.

### opencti-get-incidents

***
Get incidents in OpenCTI.

#### Base Command

`opencti-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | The incident's value to filter by. Can be a partial value. | Optional |
| created_by | The ID of the entity that created the incident (use opencti-organization-list to find or create). | Optional |
| creator | The ID of the incident creator. | Optional |
| created_after | Created after date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| created_before | Created before date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| incident_types | The types of the incident. Use opencti-incident-types-list to find all incident types in OpenCTI. | Optional |
| label_id | The label ID for the incident (use opencti-label-list to find or create). | Optional |
| limit | The maximum number of incidents to return. Maximum value is 500. Default is 50. | Optional |
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.Incidents.LastRunID context path. | Optional |
| additional_filters | List of filters to apply. Format: [{key: str, operator: str, values: list[str], mode: str}, ...]. | Optional |
| all_results | When the argument is set to true, the limit argument is ignored. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Incidents.IncidentList.id | string | Unique ID of the incident. |
| OpenCTI.Incidents.IncidentList.name | string | Name of the incident. |
| OpenCTI.Incidents.IncidentList.description | string | Description of the incident. |
| OpenCTI.Incidents.IncidentList.source | string | The source of the incident. |
| OpenCTI.Incidents.IncidentList.severity | string | The severity of the incident. |
| OpenCTI.Incidents.IncidentList.objective | string | The objective date of the incident. |
| OpenCTI.Incidents.IncidentList.confidence | number | Confidence of the incident. |
| OpenCTI.Incidents.IncidentList.createdBy | string | Name of the entity that created the incident. |
| OpenCTI.Incidents.IncidentList.creators | list | Name of the incident creators. |
| OpenCTI.Incidents.IncidentList.labels | list | Labels associated with the incident. |
| OpenCTI.Incidents.IncidentList.incidentTypes | list | Types of the incident. |
| OpenCTI.Incidents.IncidentList.created | string | Creation date of the incident. |
| OpenCTI.Incidents.IncidentList.updatedAt | string | Last update date of the incident. |
| OpenCTI.Incidents.LastRunID | string | The last ID of the previous fetch for pagination. |

#### Command example

```!opencti-get-incidents limit=2 search="XSOAR Docs Incident"```

#### Context Example

```json
{
    "OpenCTI": {
        "Incidents": [
            {
                "IncidentList": [
                    {
                        "confidence": 50,
                        "created": "2026-11-05T15:51:03.144Z",
                        "createdBy": "",
                        "creators": null,
                        "description": "Incident created from Cortex XSOAR.",
                        "id": "de1d63ab-2081-4c33-a36f-25412f7ff42b",
                        "incidentTypes": null,
                        "labels": null,
                        "name": "XSOAR Docs Incident",
                        "objective": null,
                        "severity": null,
                        "source": null,
                        "updatedAt": "2026-11-05T15:51:03.202Z"
                    },
                    {
                        "confidence": 50,
                        "created": "2026-01-27T09:50:41.000Z",
                        "createdBy": "Microsoft Defender Incidents",
                        "creators": null,
                        "description": "A service was created or started after suspicious activities were detected. This might be an attempt to launch malicious code automatically and establish persistence.\n\nRecommended Actions:\n\n1. Review the file and the process that is responsible for creating or starting the service. If the process is unfamiliar and the executable is not a signed system file, submit the file for deep analysis and review detailed behavioral information from the analysis results. \n2. Review the machine timeline for any suspicious activities that have occurred around the time of the alert. Identify and review other affected machines. \n3. Update antivirus signatures and run a full malware scan to reveal any related components.\n4. If confirmed malicious, contain and mitigate the breach. Stop suspicious processes, isolate affected machines, decommission compromised accounts or reset their passwords, block IP addresses and URLs, and install security updates.",
                        "id": "3d22aa33-d61a-4590-b17e-88ebc19236f5",
                        "incidentTypes": null,
                        "labels": [
                            "execution"
                        ],
                        "name": "Suspicious service",
                        "objective": null,
                        "severity": "medium",
                        "source": "Microsoft Defender",
                        "updatedAt": "2026-07-10T20:56:11.711Z"
                    }
                ]
            },
            {
                "lastRunID": "WzEwLjgyNzE1LCJpbmNpZGVudC0tMDAwNWMxNTMtODY2YS01ZDIzLWJmYjYtZDUzMGY0MzhlZjlmIl0="
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents
>
>|Id|Name|Description|Source|Confidence|Severity|Objective|Created By|Creators|Labels|Incident Types|Created|Updated At|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| de1d63ab-2081-4c33-a36f-25412f7ff42b | XSOAR Docs Incident | Incident created from Cortex XSOAR. |  | 50 |  |  |  |  |  |  | 2026-11-05T15:51:03.144Z | 2026-11-05T15:51:03.202Z |
>| 3d22aa33-d61a-4590-b17e-88ebc19236f5 | Suspicious service | A service was created or started after suspicious activities were detected. This might be an attempt to launch malicious code automatically and establish persistence.<br/><br/>Recommended Actions:<br/><br/>1. Review the file and the process that is responsible for creating or starting the service. If the process is unfamiliar and the executable is not a signed system file, submit the file for deep analysis and review detailed behavioral information from the analysis results. <br/>2. Review the machine timeline for any suspicious activities that have occurred around the time of the alert. Identify and review other affected machines. <br/>3. Update antivirus signatures and run a full malware scan to reveal any related components.<br/>4. If confirmed malicious, contain and mitigate the breach. Stop suspicious processes, isolate affected machines, decommission compromised accounts or reset their passwords, block IP addresses and URLs, and install security updates. | Microsoft Defender | 50 | medium |  | Microsoft Defender Incidents |  | execution |  | 2026-01-27T09:50:41.000Z | 2026-07-10T20:56:11.711Z |

#### Command example

```!opencti-get-incidents additional_filters=`[{"key": "description","operator": "eq","values": ["create incident"],"mode": "and"}]````

#### Human Readable Output

>No incidents.

### opencti-incident-types-list

***
Get a list of all incident types.

#### Base Command

`opencti-incident-types-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.IncidentTypes.IncidentTypesList.id | unknown | Incident type ID. |
| OpenCTI.IncidentTypes.IncidentTypesList.name | unknown | Incident type name. |
| OpenCTI.IncidentTypes.IncidentTypesList.description | unknown | Incident type description. |

#### Command example

```!opencti-incident-types-list```

#### Context Example

```json
{
    "OpenCTI": {
        "IncidentTypes": {
            "IncidentTypesList": [
                {
                    "description": "An alert.",
                    "id": "c19f2480-92c0-4b49-8b68-0855b25c06c2",
                    "name": "Alert"
                },
                {
                    "description": "A compromise.",
                    "id": "c7e19eae-4a76-403b-935a-719cf011c153",
                    "name": "compromise"
                },
                {
                    "description": null,
                    "id": "ad2ec1b5-685c-4061-bb3f-385029cd0f29",
                    "name": "Compromised Credentials"
                },
                {
                    "description": "Related to cybercrime.",
                    "id": "b48b9ce8-565a-49fb-872b-da274ba4c2a2",
                    "name": "cybercrime"
                },
                {
                    "description": "A data leak.",
                    "id": "881ff35b-00a9-445c-8bc1-9b9be2c680e5",
                    "name": "data-leak"
                },
                {
                    "description": null,
                    "id": "0b563245-09d5-4053-983d-34ee0b7c597e",
                    "name": "Document"
                },
                {
                    "description": null,
                    "id": "9919941b-8ee1-46c4-80ea-d6103d26cd54",
                    "name": "Domain Discovery"
                },
                {
                    "description": "Disruption in the information system.",
                    "id": "d05877af-92ce-42de-b638-edf3720a1ad2",
                    "name": "information-system-disruption"
                },
                {
                    "description": "A phishing attack.",
                    "id": "05359939-1ca0-44c3-9113-b6bcf50610ac",
                    "name": "phishing"
                },
                {
                    "description": "A ransomware.",
                    "id": "3b8b861e-7730-4c3e-98e4-32c61660b739",
                    "name": "ransomware"
                },
                {
                    "description": "Damage to reputation.",
                    "id": "3a2578ab-d7db-4a92-8887-8eb760db9400",
                    "name": "reputation-damage"
                },
                {
                    "description": "A typosquatting.",
                    "id": "01c385c5-0399-4ba8-a892-7cf97d773320",
                    "name": "typosquatting"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Incident Types
>
>|Id|Name|Description|
>|---|---|---|
>| c19f2480-92c0-4b49-8b68-0855b25c06c2 | Alert | An alert. |
>| c7e19eae-4a76-403b-935a-719cf011c153 | compromise | A compromise. |
>| ad2ec1b5-685c-4061-bb3f-385029cd0f29 | Compromised Credentials |  |
>| b48b9ce8-565a-49fb-872b-da274ba4c2a2 | cybercrime | Related to cybercrime. |
>| 881ff35b-00a9-445c-8bc1-9b9be2c680e5 | data-leak | A data leak. |
>| 0b563245-09d5-4053-983d-34ee0b7c597e | Document |  |
>| 9919941b-8ee1-46c4-80ea-d6103d26cd54 | Domain Discovery |  |
>| d05877af-92ce-42de-b638-edf3720a1ad2 | information-system-disruption | Disruption in the information system. |
>| 05359939-1ca0-44c3-9113-b6bcf50610ac | phishing | A phishing attack. |
>| 3b8b861e-7730-4c3e-98e4-32c61660b739 | ransomware | A ransomware. |
>| 3a2578ab-d7db-4a92-8887-8eb760db9400 | reputation-damage | Damage to reputation. |
>| 01c385c5-0399-4ba8-a892-7cf97d773320 | typosquatting | A typosquatting. |

### opencti-indicator-create

***
Create a new indicator in OpenCTI.

#### Base Command

`opencti-indicator-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the indicator. | Required |
| indicator | Value of the indicator. | Required |
| main_observable_type | Main observable type for the indicator. Possible values are: Account, Domain, Email, File-MD5, File-SHA1, File-SHA256, IP, IPv6, Registry Key, URL. | Required |
| indicator_types | The types of the indicator. Use opencti-indicator-types-list to find all indicator types in OpenCTI. | Optional |
| description | The description of the indicator. | Optional |
| confidence | Confidence level for the indicator, value between 0 and 100. Default is 50. | Optional |
| score | The score of the indicator, value between 0 and 100. Default is 50. | Optional |
| valid_from | The valid-from date for the indicator in the format YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| valid_until | The valid-until date for the indicator in the format YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| created_by | The ID of the entity that created the indicator (use opencti-organization-list to find or create). | Optional |
| label_id | The label ID for the indicator (use opencti-label-list to find or create). | Optional |
| marking_id | The marking ID for the indicator (use opencti-marking-definition-list to find). | Optional |
| external_references_id | External references ID for the indicator (use opencti-external-reference-create to create). | Optional |
| create_observables | Create OpenCTI observable related to the OpenCTI indicator created. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicator.id | string | New indicator ID. |

#### Command example

```!opencti-indicator-create name=ExampleIndicator indicator="198.51.100.7" main_observable_type=IP```

#### Context Example

```json
{
    "OpenCTI": {
        "Indicator": {
            "id": "910756cd-4803-42f3-9c82-2977c7e95c92"
        }
    }
}
```

#### Human Readable Output

>Indicator created successfully. New Indicator id: 910756cd-4803-42f3-9c82-2977c7e95c92.

### opencti-indicator-field-add

***
Add a field to the indicator. Fields that can be added are marking definition and label.

#### Base Command

`opencti-indicator-field-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required |
| field | Indicator field to add. Possible values are: marking, label. | Required |
| value | Value of the field to add. Enter label ID or marking definition ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!opencti-indicator-field-add id=7203be86-63ed-4ffd-992b-0ab76611b96e field=marking value=936174b6-df6d-4370-ae76-97b03fb438b8```

#### Human Readable Output

>Added marking successfully.

### opencti-indicator-field-remove

***
Remove indicator field value. Fields whose values can be removed are marking definition and label.

#### Base Command

`opencti-indicator-field-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required |
| field | Indicator field to update. Possible values are: marking, label. | Required |
| value | Value of the field to remove. Enter label ID or marking definition ID. Use opencti-label-list to find all label IDs in OpenCTI or opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!opencti-indicator-field-remove id=7203be86-63ed-4ffd-992b-0ab76611b96e field=marking value=936174b6-df6d-4370-ae76-97b03fb438b8```

#### Human Readable Output

>marking: 936174b6-df6d-4370-ae76-97b03fb438b8 was removed successfully from indicator: 7203be86-63ed-4ffd-992b-0ab76611b96e.

### opencti-indicator-update

***
Update a indicator in OpenCTI.

#### Base Command

`opencti-indicator-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the indicator. | Required |
| name | Name of the indicator. | Optional |
| indicator_types | The types of the indicator. Use opencti-indicator-types-list to find all indicator types in OpenCTI. | Optional |
| description | The description of the indicator. | Optional |
| confidence | Confidence level for the indicator, value between 0 and 100. Default is 50. | Optional |
| score | The score of the indicator, value between 0 and 100. Default is 50. | Optional |
| valid_from | The valid-from date for the indicator in the format YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| valid_until | The valid-until date for the indicator in the format YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| label_id | The label ID for the indicator (use opencti-label-list to find or create). | Optional |
| marking_id | The marking ID for the indicator (use opencti-marking-definition-list to find). | Optional |
| external_references_id | External references ID for the indicator (use opencti-external-reference-create to create). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicator.id | string | New indicator ID. |
| OpenCTI.Indicator.name | string | Name of the updated indicator. |
| OpenCTI.Indicator.validFrom | string | The valid-from date of the updated indicator. |
| OpenCTI.Indicator.validUntil | string | The valid-until date of the updated indicator. |

#### Command example

```!opencti-indicator-update id=7203be86-63ed-4ffd-992b-0ab76611b96e name=ExampleIndicator2```

#### Context Example

```json
{
    "OpenCTI": {
        "Indicator": {
            "id": "7203be86-63ed-4ffd-992b-0ab76611b96e",
            "name": "ExampleIndicator2",
            "validFrom": "2026-11-05T00:00:00.000Z",
            "validUntil": "2027-09-01T15:51:54.812Z"
        }
    }
}
```

#### Human Readable Output

>Indicator updated successfully.

### opencti-get-indicators

***
Get indicators in OpenCTI.

#### Base Command

`opencti-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | The indicator's value to filter by, can be partial value. | Optional |
| created_by | The ID of the entity that created the indicator (use opencti-organization-list to find or create). | Optional |
| creator | The ID of the indicator creator. | Optional |
| created_after | Created after date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| created_before | Created before date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| valid_until_after | Valid until after date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| valid_until_before | Valid until before date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| valid_from_after | Valid from after date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| valid_from_before | Valid from before date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| indicator_types | The types of the indicator. Use opencti-indicator-types-list to find all indicator types in OpenCTI. | Optional |
| label_id | The label ID for the indicator (use opencti-label-list to find or create). | Optional |
| limit | The maximum number of indicators to return. Maximum value is 500. Default is 50. | Optional |
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.Indicators.LastRunID context path. | Optional |
| additional_filters | List of filters to apply. Format: [{key: str, operator: str, values: list[str], mode: str}, ...]. | Optional |
| all_results | When the argument is set to true, the limit argument is ignored. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicators.IndicatorList.id | string | Unique ID of the indicator. |
| OpenCTI.Indicators.IndicatorList.name | string | Name of the indicator. |
| OpenCTI.Indicators.IndicatorList.description | string | Description of the indicator. |
| OpenCTI.Indicators.IndicatorList.pattern | string | The pattern associated with the indicator. |
| OpenCTI.Indicators.IndicatorList.validFrom | string | The valid-from date of the indicator. |
| OpenCTI.Indicators.IndicatorList.validUntil | string | The valid-until date of the indicator. |
| OpenCTI.Indicators.IndicatorList.score | number | Score of the indicator. |
| OpenCTI.Indicators.IndicatorList.confidence | number | Confidence of the indicator. |
| OpenCTI.Indicators.IndicatorList.createdBy | string | Name of the entity that created the indicator. |
| OpenCTI.Indicators.IndicatorList.creators | list | Name of the indicator creators. |
| OpenCTI.Indicators.IndicatorList.labels | list | Labels associated with the indicator. |
| OpenCTI.Indicators.IndicatorList.indicatorTypes | list | Types of the indicator. |
| OpenCTI.Indicators.IndicatorList.created | string | Creation date of the indicator. |
| OpenCTI.Indicators.IndicatorList.updatedAt | string | Last update date of the indicator. |
| OpenCTI.Indicators.LastRunID | string | The last ID of the previous fetch for pagination. |

#### Command example

```!opencti-get-indicators limit=2 search=suspicious.example.com```

#### Context Example

```json
{
    "OpenCTI": {
        "Indicators": [
            {
                "IndicatorList": {
                    "confidence": 50,
                    "created": "2026-11-05T15:51:17.535Z",
                    "createdBy": "",
                    "creators": [
                        "XSOAR OpenCTI"
                    ],
                    "description": null,
                    "id": "7896fcbf-170e-42bf-a02e-ad5e66a3c7dc",
                    "indicatorTypes": null,
                    "labels": null,
                    "name": "suspicious.example.com",
                    "pattern": "[domain-name:value = 'suspicious.example.com']",
                    "score": 60,
                    "updatedAt": "2026-11-05T15:51:53.714Z",
                    "validFrom": "2026-11-05T00:00:00.000Z",
                    "validUntil": "2027-09-01T15:51:53.585Z"
                }
            },
            {
                "lastRunID": "WzExOC4wNTk1NSwiaW5kaWNhdG9yLS0xMzM5NzAxOS0wMWRmLTUyZTEtYmJhMS04ZWE1ZmI4MGJkZTIiXQ=="
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators
>
>|Id|Name|Description|Pattern|Valid From|Valid Until|Confidence|Score|Created By|Creators|Labels|Indicator Types|Created|Updated At|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 7896fcbf-170e-42bf-a02e-ad5e66a3c7dc | suspicious.example.com |  | [domain-name:value = 'suspicious.example.com'] | 2026-11-05T00:00:00.000Z | 2027-09-01T15:51:53.585Z | 50 | 60 |  | XSOAR OpenCTI |  |  | 2026-11-05T15:51:17.535Z | 2026-11-05T15:51:53.714Z |

### opencti-relationship-create

***
Create new relationship.

#### Base Command

`opencti-relationship-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_id | Source entity ID for the relationship. | Required |
| to_id | Target entity ID for the relationship. | Required |
| relationship_type | Type of relationship to create. Possible values are: uses, targets, indicates, mitigates, attributed-to, located-at, related-to, derived-from, member-of, variant-of, part-of, communicates-with, compromises, delivers, owns, authored-by, impersonates, controls, hosts, investigates. Default is related-to. | Optional |
| description | Description of the relationship. | Optional |
| confidence | Confidence Number. Values range is 0 - 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Relationship.id | unknown | New relationship ID. |
| OpenCTI.Relationship.relationshipType | unknown | New relationship type. |

#### Command example

```!opencti-relationship-create from_id=de1d63ab-2081-4c33-a36f-25412f7ff42b to_id=c288ff0e-4601-4e97-8b21-423dc08c1f83 relationship_type=related-to```

#### Context Example

```json
{
    "OpenCTI": {
        "Relationship": {
            "id": "00640892-836d-4513-a2a4-8f0ed99f0444",
            "relationshipType": null
        }
    }
}
```

#### Human Readable Output

>Relationship created successfully. New Relationship id: 00640892-836d-4513-a2a4-8f0ed99f0444.

### opencti-relationship-delete

***
Delete relationship.

#### Base Command

`opencti-relationship-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Relationship ID. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!opencti-relationship-delete id=00640892-836d-4513-a2a4-8f0ed99f0444```

#### Human Readable Output

>Relationship deleted.

### opencti-relationship-list

***
Get a list of all relationships in OpenCTI.

#### Base Command

`opencti-relationship-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_id | The relationship from entity ID. | Required |
| limit | The maximum number of relationships to return per fetch. Default value is 50. Maximum value is 200. Default is 50. | Optional |
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.Relationships.relationshipsLastRun context path. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Relationships.RelationshipsList.id | String | Relationship ID. |
| OpenCTI.Relationships.RelationshipsList.relationshipType | String | Relationship type. |
| OpenCTI.Relationships.RelationshipsList.fromId | String | Relationship from entity ID. |
| OpenCTI.Relationships.RelationshipsList.toId | String | Relationship to entity ID. |
| OpenCTI.Relationships.RelationshipsList.toEntityType | String | Relationship to entity type. |
| OpenCTI.Relationships.relationshipsLastRun | String | The last ID of the previous fetch to use for pagination. |

#### Command example

```!opencti-relationship-list from_id=de1d63ab-2081-4c33-a36f-25412f7ff42b limit=2```

#### Context Example

```json
{
    "OpenCTI": {
        "Relationships": {
            "RelationshipsList": {
                "fromId": "de1d63ab-2081-4c33-a36f-25412f7ff42b",
                "id": "00640892-836d-4513-a2a4-8f0ed99f0444",
                "relationshipType": "related-to",
                "toEntityType": "Domain-Name",
                "toId": "c288ff0e-4601-4e97-8b21-423dc08c1f83"
            },
            "relationshipsLastRun": "WyJyZWxhdGlvbnNoaXAtLTE1MTRmODU0LWFlNDUtNThhMC05MDk1LWViMDVmZWU3YTEwNSJd"
        }
    }
}
```

#### Human Readable Output

>### Relationships
>
>|Id|Relationship Type|From Id|To Id|To Entity Type|
>|---|---|---|---|---|
>| 00640892-836d-4513-a2a4-8f0ed99f0444 | related-to | de1d63ab-2081-4c33-a36f-25412f7ff42b | c288ff0e-4601-4e97-8b21-423dc08c1f83 | Domain-Name |

### opencti-indicator-types-list

***
Get a list of all indicator types.

#### Base Command

`opencti-indicator-types-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.IndicatorTypes.IndicatorTypesList.id | unknown | Indicator type ID. |
| OpenCTI.IndicatorTypes.IndicatorTypesList.name | unknown | Indicator type name. |
| OpenCTI.IndicatorTypes.IndicatorTypesList.description | unknown | Indicator type description. |

#### Command example

```!opencti-indicator-types-list```

#### Context Example

```json
{
    "OpenCTI": {
        "IndicatorTypes": {
            "IndicatorTypesList": [
                {
                    "description": null,
                    "id": "1a4f7ebe-d309-4bc9-9b92-a77f6c2f457e",
                    "name": "ActorControlled"
                },
                {
                    "description": null,
                    "id": "8852e966-ab31-483b-a2f2-a1d93588ef8a",
                    "name": "AdversaryControlled"
                },
                {
                    "description": "Unexpected, or unusual activity that may not necessarily be malicious or indicate compromise. This type of activity may include reconnaissance-like behavior such as port scans or version identification, network behavior anomalies, and asset and/or user behavioral anomalies.",
                    "id": "71cf6bc1-1a5e-4b41-bdb3-9d62533408ff",
                    "name": "anomalous-activity"
                },
                {
                    "description": "Suspected anonymization tools or infrastructure (proxy, TOR, VPN, etc.).",
                    "id": "840d908c-6ccc-4ce7-9bc5-af563b878e85",
                    "name": "anonymization"
                },
                {
                    "description": null,
                    "id": "fa693077-cc0f-4a63-93e2-b66e563af3ec",
                    "name": "AntiForensics"
                },
                {
                    "description": null,
                    "id": "8a715711-bf2e-4daa-b81f-b64c346368ff",
                    "name": "ATM_Malware"
                },
                {
                    "description": null,
                    "id": "146f8824-35be-40e0-9b0d-58095578e732",
                    "name": "AttackerTypo"
                },
                {
                    "description": "Patterns of behavior that indicate attribution to a particular Threat Actor or Campaign.",
                    "id": "8ec3226a-bbb8-4090-bab9-3c3e9a00d7e7",
                    "name": "attribution"
                },
                {
                    "description": null,
                    "id": "5c9c6f4e-2d0b-4b10-8ef9-9d5e3c20ed88",
                    "name": "Banking"
                },
                {
                    "description": "Audit that is not suspicious or malicious in and of itself, but when combined with other activity may indicate suspicious or malicious behavior.",
                    "id": "9eb9b73f-f4d1-49e2-9a33-95e6c3b246d8",
                    "name": "benign"
                },
                {
                    "description": null,
                    "id": "884ed7dc-9fbe-4a0f-9de2-8d95c60dca4b",
                    "name": "BruteForce"
                },
                {
                    "description": null,
                    "id": "588a1c88-3bc6-4328-b05f-a2d63706b83e",
                    "name": "CDN"
                },
                {
                    "description": null,
                    "id": "8b5babc9-7b1e-4922-b4c8-2dc26f431cf3",
                    "name": "ClickFraud"
                },
                {
                    "description": null,
                    "id": "2d7993d7-2cf4-4e36-8e8b-e8c49d747b70",
                    "name": "Commodity"
                },
                {
                    "description": "Assets that are suspected to be compromised.",
                    "id": "b598fc49-f6d4-42df-bb6f-91043903bbd3",
                    "name": "compromised"
                },
                {
                    "description": null,
                    "id": "e472982b-a0d9-44ca-91d7-8404457e2bc0",
                    "name": "CredentialHarvesting"
                },
                {
                    "description": null,
                    "id": "77d240f1-a3bd-4b39-ad3e-121011b69139",
                    "name": "CryptoCurrencyTheft"
                },
                {
                    "description": null,
                    "id": "d9825a18-3bd1-4e9e-83e9-3d7b5d438d45",
                    "name": "DeploymentFramework"
                },
                {
                    "description": null,
                    "id": "5ed383a3-4ff2-43b8-a768-96d7d4529fdc",
                    "name": "Destructive/Wiper"
                },
                {
                    "description": null,
                    "id": "6e19be93-9e53-49c8-998b-e4e20f0d1571",
                    "name": "DGA"
                },
                {
                    "description": null,
                    "id": "4f31af3f-d156-4c1d-b280-790090e5dd84",
                    "name": "DisableDefensiveTooling"
                },
                {
                    "description": null,
                    "id": "de98585b-9eba-4e58-97d1-77633cd67199",
                    "name": "DynamicDNS"
                },
                {
                    "description": null,
                    "id": "bfe1677f-da22-4a6c-bebc-3233864b0a67",
                    "name": "DynamicDNS/DYN"
                },
                {
                    "description": null,
                    "id": "db67dde8-a82c-4560-88b0-6a61a87ae742",
                    "name": "ExploitKit"
                },
                {
                    "description": null,
                    "id": "610373f3-de30-428c-bdcc-d9f6d8427810",
                    "name": "FileInfector"
                },
                {
                    "description": null,
                    "id": "dce1ce5e-02e8-4809-b9dc-4bf8b4b62aa3",
                    "name": "FileSharingProvider"
                },
                {
                    "description": null,
                    "id": "600ec608-d63d-44e6-abaf-c7c608b0cf3b",
                    "name": "Formjacking"
                },
                {
                    "description": null,
                    "id": "a1676cb2-49df-4b2b-ad78-3f91238f61df",
                    "name": "GenericThreatCategory"
                },
                {
                    "description": null,
                    "id": "bf64453e-bbd5-4db4-9faf-5bbbfce3ae7d",
                    "name": "HostingProvider"
                },
                {
                    "description": null,
                    "id": "ef1c7a41-fc7b-478e-9299-eb423d9edfe5",
                    "name": "InformationStealer"
                },
                {
                    "description": null,
                    "id": "284bde53-8cdf-4675-a776-055cb4cacb16",
                    "name": "KnownGood"
                },
                {
                    "description": null,
                    "id": "1bf241a6-8ac1-42c8-b74e-10eb8a61be31",
                    "name": "LegitimateCompromised"
                },
                {
                    "description": null,
                    "id": "a6a3902c-7d66-4921-998d-69e1b0e15293",
                    "name": "LegitimateSoftware"
                },
                {
                    "description": "Patterns of suspected malicious objects and/or activity.",
                    "id": "615c170f-ccea-419f-85c2-3a17e29d7ad1",
                    "name": "malicious-activity"
                },
                {
                    "description": null,
                    "id": "69e2031a-3ec9-4a59-83d6-7d1a17fb2afa",
                    "name": "MaliciousScript"
                },
                {
                    "description": null,
                    "id": "1b63f252-48b5-46ec-a79c-feb7a8c6c478",
                    "name": "Mineware"
                },
                {
                    "description": null,
                    "id": "42dfcb58-ec7b-442d-bfb2-bde45447d3dc",
                    "name": "MobileMalware"
                },
                {
                    "description": null,
                    "id": "8cfe9afe-2daf-40b3-b83d-5df9f09a948b",
                    "name": "Modular"
                },
                {
                    "description": null,
                    "id": "af3036b9-8c52-4c4f-93fd-68a6e65258fb",
                    "name": "NetworkScanner"
                },
                {
                    "description": null,
                    "id": "cfe3fc69-d71b-4af0-9dd5-5acdeb967bed",
                    "name": "OpenSource"
                },
                {
                    "description": null,
                    "id": "7ab7e94a-535e-46fb-b007-3402d8d4ef0f",
                    "name": "PaymentAddress"
                },
                {
                    "description": null,
                    "id": "3b99389d-7697-4435-ac7d-6737734c2a29",
                    "name": "PointOfSale"
                },
                {
                    "description": null,
                    "id": "137f3db1-2e3d-4ee0-8166-074ffedd86f2",
                    "name": "Polymorphic"
                },
                {
                    "description": null,
                    "id": "280061ca-07c4-42b4-abb0-1c059440a6b0",
                    "name": "Popular"
                },
                {
                    "description": null,
                    "id": "49785a60-19a5-4b79-8132-ad118138abf8",
                    "name": "Popular/SubdomainsOK"
                },
                {
                    "description": null,
                    "id": "afb14beb-4b16-4ff0-8b63-13f780abcd0d",
                    "name": "PopularSite"
                },
                {
                    "description": null,
                    "id": "f679ca98-5876-4401-b279-21e4f8eadb56",
                    "name": "PrivateAddress"
                },
                {
                    "description": null,
                    "id": "f690891e-76ba-4a00-b360-cbcc2dd763b1",
                    "name": "PrivilegeEscalation"
                },
                {
                    "description": null,
                    "id": "c6d8a415-fc21-4e18-890b-ce08f3ad3a77",
                    "name": "ProvidedAsAService"
                },
                {
                    "description": null,
                    "id": "60a60d56-5f6d-4d6a-8cc7-4c586208b98e",
                    "name": "PUP"
                },
                {
                    "description": null,
                    "id": "9214e9a7-7d16-4958-9faa-8a88eb959b7e",
                    "name": "RAT"
                },
                {
                    "description": null,
                    "id": "5c048b08-7efe-46ea-8084-a44649fa6b01",
                    "name": "RepurposedLegitimateSoftware"
                },
                {
                    "description": null,
                    "id": "fa5fd35e-4545-40f6-b781-3f9204407a0f",
                    "name": "SabotageOperationalTechnology"
                },
                {
                    "description": null,
                    "id": "160e30b8-db7c-4333-934b-5444ebff5876",
                    "name": "Sideloading"
                },
                {
                    "description": null,
                    "id": "f4d2a77d-69a0-4a7d-8924-288986b4cfc0",
                    "name": "Sinkholed"
                },
                {
                    "description": null,
                    "id": "3c50068b-a69e-4651-80ae-ce5c592b700f",
                    "name": "SourceCodeLeaked"
                },
                {
                    "description": null,
                    "id": "b55eda02-cb9d-4882-8389-1b11732eeba8",
                    "name": "SSHScanner"
                },
                {
                    "description": null,
                    "id": "7a3b11c1-7cac-4bff-928d-53073637e4a5",
                    "name": "StrategicWebCompromise"
                },
                {
                    "description": null,
                    "id": "638ba61d-0dab-41e3-9cce-ec715b631dbf",
                    "name": "Targeted"
                },
                {
                    "description": null,
                    "id": "719a052c-b1ac-44d2-a1d1-e2c9caab3209",
                    "name": "TargetedCrimeware"
                },
                {
                    "description": null,
                    "id": "df25bdaf-27c2-4063-b625-01d2d44f31d9",
                    "name": "Test"
                },
                {
                    "description": null,
                    "id": "2f3a9879-e66a-4c2b-8c01-9b99e1e63173",
                    "name": "TorExit"
                },
                {
                    "description": "There is not enough information available to determine the type of indicator.",
                    "id": "21b796ed-dbe1-4c37-8369-e8c6eec3061c",
                    "name": "unknown"
                },
                {
                    "description": null,
                    "id": "bfebc3df-0d59-4445-899b-408d9b09db13",
                    "name": "VERDICT_BENIGN"
                },
                {
                    "description": null,
                    "id": "e417a6fa-6dd2-4275-b8bf-d95dcdbb5e2c",
                    "name": "VERDICT_MALICIOUS"
                },
                {
                    "description": null,
                    "id": "6d6f30dd-186e-4dd4-8cbf-129fa95499be",
                    "name": "VERDICT_SUSPICIOUS"
                },
                {
                    "description": null,
                    "id": "81278e9c-7a36-445a-84a0-67e111ad014c",
                    "name": "VERDICT_UNDETECTED"
                },
                {
                    "description": null,
                    "id": "e8f311c0-c22a-42f1-b185-cbbda2138b2f",
                    "name": "VERDICT_UNKNOWN"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Indicator Types
>
>|Id|Name|Description|
>|---|---|---|
>| 1a4f7ebe-d309-4bc9-9b92-a77f6c2f457e | ActorControlled |  |
>| 8852e966-ab31-483b-a2f2-a1d93588ef8a | AdversaryControlled |  |
>| 71cf6bc1-1a5e-4b41-bdb3-9d62533408ff | anomalous-activity | Unexpected, or unusual activity that may not necessarily be malicious or indicate compromise. This type of activity may include reconnaissance-like behavior such as port scans or version identification, network behavior anomalies, and asset and/or user behavioral anomalies. |
>| 840d908c-6ccc-4ce7-9bc5-af563b878e85 | anonymization | Suspected anonymization tools or infrastructure (proxy, TOR, VPN, etc.). |
>| fa693077-cc0f-4a63-93e2-b66e563af3ec | AntiForensics |  |
>| 8a715711-bf2e-4daa-b81f-b64c346368ff | ATM_Malware |  |
>| 146f8824-35be-40e0-9b0d-58095578e732 | AttackerTypo |  |
>| 8ec3226a-bbb8-4090-bab9-3c3e9a00d7e7 | attribution | Patterns of behavior that indicate attribution to a particular Threat Actor or Campaign. |
>| 5c9c6f4e-2d0b-4b10-8ef9-9d5e3c20ed88 | Banking |  |
>| 9eb9b73f-f4d1-49e2-9a33-95e6c3b246d8 | benign | Audit that is not suspicious or malicious in and of itself, but when combined with other activity may indicate suspicious or malicious behavior. |
>| 884ed7dc-9fbe-4a0f-9de2-8d95c60dca4b | BruteForce |  |
>| 588a1c88-3bc6-4328-b05f-a2d63706b83e | CDN |  |
>| 8b5babc9-7b1e-4922-b4c8-2dc26f431cf3 | ClickFraud |  |
>| 2d7993d7-2cf4-4e36-8e8b-e8c49d747b70 | Commodity |  |
>| b598fc49-f6d4-42df-bb6f-91043903bbd3 | compromised | Assets that are suspected to be compromised. |
>| e472982b-a0d9-44ca-91d7-8404457e2bc0 | CredentialHarvesting |  |
>| 77d240f1-a3bd-4b39-ad3e-121011b69139 | CryptoCurrencyTheft |  |
>| d9825a18-3bd1-4e9e-83e9-3d7b5d438d45 | DeploymentFramework |  |
>| 5ed383a3-4ff2-43b8-a768-96d7d4529fdc | Destructive/Wiper |  |
>| 6e19be93-9e53-49c8-998b-e4e20f0d1571 | DGA |  |
>| 4f31af3f-d156-4c1d-b280-790090e5dd84 | DisableDefensiveTooling |  |
>| de98585b-9eba-4e58-97d1-77633cd67199 | DynamicDNS |  |
>| bfe1677f-da22-4a6c-bebc-3233864b0a67 | DynamicDNS/DYN |  |
>| db67dde8-a82c-4560-88b0-6a61a87ae742 | ExploitKit |  |
>| 610373f3-de30-428c-bdcc-d9f6d8427810 | FileInfector |  |
>| dce1ce5e-02e8-4809-b9dc-4bf8b4b62aa3 | FileSharingProvider |  |
>| 600ec608-d63d-44e6-abaf-c7c608b0cf3b | Formjacking |  |
>| a1676cb2-49df-4b2b-ad78-3f91238f61df | GenericThreatCategory |  |
>| bf64453e-bbd5-4db4-9faf-5bbbfce3ae7d | HostingProvider |  |
>| ef1c7a41-fc7b-478e-9299-eb423d9edfe5 | InformationStealer |  |
>| 284bde53-8cdf-4675-a776-055cb4cacb16 | KnownGood |  |
>| 1bf241a6-8ac1-42c8-b74e-10eb8a61be31 | LegitimateCompromised |  |
>| a6a3902c-7d66-4921-998d-69e1b0e15293 | LegitimateSoftware |  |
>| 615c170f-ccea-419f-85c2-3a17e29d7ad1 | malicious-activity | Patterns of suspected malicious objects and/or activity. |
>| 69e2031a-3ec9-4a59-83d6-7d1a17fb2afa | MaliciousScript |  |
>| 1b63f252-48b5-46ec-a79c-feb7a8c6c478 | Mineware |  |
>| 42dfcb58-ec7b-442d-bfb2-bde45447d3dc | MobileMalware |  |
>| 8cfe9afe-2daf-40b3-b83d-5df9f09a948b | Modular |  |
>| af3036b9-8c52-4c4f-93fd-68a6e65258fb | NetworkScanner |  |
>| cfe3fc69-d71b-4af0-9dd5-5acdeb967bed | OpenSource |  |
>| 7ab7e94a-535e-46fb-b007-3402d8d4ef0f | PaymentAddress |  |
>| 3b99389d-7697-4435-ac7d-6737734c2a29 | PointOfSale |  |
>| 137f3db1-2e3d-4ee0-8166-074ffedd86f2 | Polymorphic |  |
>| 280061ca-07c4-42b4-abb0-1c059440a6b0 | Popular |  |
>| 49785a60-19a5-4b79-8132-ad118138abf8 | Popular/SubdomainsOK |  |
>| afb14beb-4b16-4ff0-8b63-13f780abcd0d | PopularSite |  |
>| f679ca98-5876-4401-b279-21e4f8eadb56 | PrivateAddress |  |
>| f690891e-76ba-4a00-b360-cbcc2dd763b1 | PrivilegeEscalation |  |
>| c6d8a415-fc21-4e18-890b-ce08f3ad3a77 | ProvidedAsAService |  |
>| 60a60d56-5f6d-4d6a-8cc7-4c586208b98e | PUP |  |
>| 9214e9a7-7d16-4958-9faa-8a88eb959b7e | RAT |  |
>| 5c048b08-7efe-46ea-8084-a44649fa6b01 | RepurposedLegitimateSoftware |  |
>| fa5fd35e-4545-40f6-b781-3f9204407a0f | SabotageOperationalTechnology |  |
>| 160e30b8-db7c-4333-934b-5444ebff5876 | Sideloading |  |
>| f4d2a77d-69a0-4a7d-8924-288986b4cfc0 | Sinkholed |  |
>| 3c50068b-a69e-4651-80ae-ce5c592b700f | SourceCodeLeaked |  |
>| b55eda02-cb9d-4882-8389-1b11732eeba8 | SSHScanner |  |
>| 7a3b11c1-7cac-4bff-928d-53073637e4a5 | StrategicWebCompromise |  |
>| 638ba61d-0dab-41e3-9cce-ec715b631dbf | Targeted |  |
>| 719a052c-b1ac-44d2-a1d1-e2c9caab3209 | TargetedCrimeware |  |
>| df25bdaf-27c2-4063-b625-01d2d44f31d9 | Test |  |
>| 2f3a9879-e66a-4c2b-8c01-9b99e1e63173 | TorExit |  |
>| 21b796ed-dbe1-4c37-8369-e8c6eec3061c | unknown | There is not enough information available to determine the type of indicator. |
>| bfebc3df-0d59-4445-899b-408d9b09db13 | VERDICT_BENIGN |  |
>| e417a6fa-6dd2-4275-b8bf-d95dcdbb5e2c | VERDICT_MALICIOUS |  |
>| 6d6f30dd-186e-4dd4-8cbf-129fa95499be | VERDICT_SUSPICIOUS |  |
>| 81278e9c-7a36-445a-84a0-67e111ad014c | VERDICT_UNDETECTED |  |
>| e8f311c0-c22a-42f1-b185-cbbda2138b2f | VERDICT_UNKNOWN |  |

### opencti-incident-response-create

***
Creates a new incident response.

#### Base Command

`opencti-incident-response-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Incident Response name. | Required |
| incident_response_type | Incident Response type name. Use opencti-incident-response-types-list to find all incident response types in OpenCTI. | Optional |
| severity | Incident Response severity. Possible values are: low, medium, high, critical. | Optional |
| priority | Incident Response priority. Possible values are: P1, P2, P3, P4. | Optional |
| description | Incident Response description. | Optional |
| created_by | Organization ID. Use opencti-organization-list to find all organization IDs in OpenCTI, or use opencti-organization-create to create a new organization ID. | Optional |
| incident_response_date | Incident Response date and time (ISO 8601 format, for example, 2020-01-01T00:11:22.000Z). | Optional |
| label_id | Incident Response label ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. | Optional |
| marking_id | Incident Response marking definition ID. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Optional |
| external_references_id | External reference ID. Use opencti-external-reference-create to create a new external reference. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.IncidentResponse.id | String | New incident response ID. |

#### Command example

```!opencti-incident-response-create name="Example Incident Response" severity=high priority=P2 description="Incident response created from Cortex XSOAR." incident_response_date=2025-01-15T09:30:00.000Z```

#### Context Example

```json
{
    "OpenCTI": {
        "IncidentResponse": {
            "id": "aa8ac466-f461-44fe-a50f-dc6547a33ce4"
        }
    }
}
```

#### Human Readable Output

>Incident response created successfully. New Incident Response id: aa8ac466-f461-44fe-a50f-dc6547a33ce4.

### opencti-incident-response-types-list

***
Gets a list of all incident response types.

#### Base Command

`opencti-incident-response-types-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.IncidentResponseTypes.IncidentResponseTypesList.id | String | Incident response type ID. |
| OpenCTI.IncidentResponseTypes.IncidentResponseTypesList.name | String | Incident response type name. |
| OpenCTI.IncidentResponseTypes.IncidentResponseTypesList.description | String | Incident response type description. |

#### Command example

```!opencti-incident-response-types-list```

#### Context Example

```json
{
    "OpenCTI": {
        "IncidentResponseTypes": {
            "IncidentResponseTypesList": [
                {
                    "description": null,
                    "id": "d3df0969-fa70-4eb9-a8ce-29e31b36179c",
                    "name": "Alert"
                },
                {
                    "description": "A data-leak",
                    "id": "5df8586b-6b3e-477b-81db-dc4b0311d424",
                    "name": "data-leak"
                },
                {
                    "description": "A ransomware",
                    "id": "bbb07e82-9a9c-41e0-b240-23b47217fedc",
                    "name": "ransomware"
                },
                {
                    "description": "",
                    "id": "11f0bff1-e471-414b-b9a1-e09fa9a47bfa",
                    "name": "Vulnerability-Exploit"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Incident Response Types
>
>|Id|Name|Description|
>|---|---|---|
>| d3df0969-fa70-4eb9-a8ce-29e31b36179c | Alert |  |
>| 5df8586b-6b3e-477b-81db-dc4b0311d424 | data-leak | A data-leak |
>| bbb07e82-9a9c-41e0-b240-23b47217fedc | ransomware | A ransomware |
>| 11f0bff1-e471-414b-b9a1-e09fa9a47bfa | Vulnerability-Exploit |  |

### opencti-malware-create

***
Creates a new malware.

#### Base Command

`opencti-malware-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the malware. | Required |
| description | Description of the malware. | Optional |
| malware_types | Comma-separated list of malware types. | Optional |
| is_family | Whether this is a malware family. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Malware.id | String | New malware ID. |

#### Command example

```!opencti-malware-create name="Example Malware" malware_types=ransomware,worm is_family=true```

#### Context Example

```json
{
    "OpenCTI": {
        "Malware": {
            "id": "3acca559-02a4-4b9a-81ee-afaf34c7a056"
        }
    }
}
```

#### Human Readable Output

>Malware created successfully. New Malware id: 3acca559-02a4-4b9a-81ee-afaf34c7a056.

### opencti-vulnerability-create

***
Creates a new vulnerability.

#### Base Command

`opencti-vulnerability-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the vulnerability (for example, CVE-2025-0001). | Required |
| description | Description of the vulnerability. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Vulnerability.id | String | New vulnerability ID. |

#### Command example

```!opencti-vulnerability-create name=CVE-2025-0001 description="Vulnerability created from Cortex XSOAR."```

#### Context Example

```json
{
    "OpenCTI": {
        "Vulnerability": {
            "id": "1130e101-a250-430a-9bb5-04b978ee2e1e"
        }
    }
}
```

#### Human Readable Output

>Vulnerability created successfully. New Vulnerability id: 1130e101-a250-430a-9bb5-04b978ee2e1e.

### opencti-intrusion-set-create

***
Creates a new intrusion set.

#### Base Command

`opencti-intrusion-set-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the intrusion set. | Required |
| description | Description of the intrusion set. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.IntrusionSet.id | String | New intrusion set ID. |

#### Command example

```!opencti-intrusion-set-create name="Example Intrusion Set"```

#### Context Example

```json
{
    "OpenCTI": {
        "IntrusionSet": {
            "id": "f26867f1-0eb6-473c-8a72-db20f683e54c"
        }
    }
}
```

#### Human Readable Output

>Intrusion set created successfully. New Intrusion Set id: f26867f1-0eb6-473c-8a72-db20f683e54c.

### opencti-threat-actor-group-create

***
Creates a new threat actor group.

#### Base Command

`opencti-threat-actor-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the threat actor group. | Required |
| description | Description of the threat actor group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.ThreatActorGroup.id | String | New threat actor group ID. |

#### Command example

```!opencti-threat-actor-group-create name="Example Threat Actor Group"```

#### Context Example

```json
{
    "OpenCTI": {
        "ThreatActorGroup": {
            "id": "9843b91a-a8b3-460c-9298-e68b159c3168"
        }
    }
}
```

#### Human Readable Output

>Threat Actor Group created successfully. New Threat Actor Group id: 9843b91a-a8b3-460c-9298-e68b159c3168.

### opencti-campaign-create

***
Creates a new campaign.

#### Base Command

`opencti-campaign-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the campaign. | Required |
| description | Description of the campaign. | Optional |
| first_seen | First seen date and time (ISO 8601 format, for example, 2020-01-01T00:11:22Z). | Optional |
| last_seen | Last seen date and time (ISO 8601 format, for example, 2020-01-01T00:11:22Z). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Campaign.id | String | New campaign ID. |

#### Command example

```!opencti-campaign-create name="Example Campaign" first_seen=2025-01-01T00:00:00Z last_seen=2025-06-30T00:00:00Z```

#### Context Example

```json
{
    "OpenCTI": {
        "Campaign": {
            "id": "1cdf4b80-c113-4f06-b371-dee3c33eb4bd"
        }
    }
}
```

#### Human Readable Output

>Campaign created successfully. New Campaign id: 1cdf4b80-c113-4f06-b371-dee3c33eb4bd.

### opencti-grouping-create

***
Creates a new grouping.

#### Base Command

`opencti-grouping-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the grouping. | Required |
| description | Description of the grouping. | Optional |
| context | Context of the grouping. Use opencti-grouping-context-list to find all grouping contexts in OpenCTI. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Grouping.id | String | New grouping ID. |

#### Command example

```!opencti-grouping-create name="Example Grouping" context=suspicious-activity```

#### Context Example

```json
{
    "OpenCTI": {
        "Grouping": {
            "id": "ff26c61c-bbab-49c3-8e72-d8085b2b8e73"
        }
    }
}
```

#### Human Readable Output

>Grouping created successfully. New Grouping id: ff26c61c-bbab-49c3-8e72-d8085b2b8e73.

### opencti-grouping-context-list

***
Gets a list of all grouping contexts.

#### Base Command

`opencti-grouping-context-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.GroupingContexts.GroupingContextsList.id | String | Grouping context ID. |
| OpenCTI.GroupingContexts.GroupingContextsList.name | String | Grouping context name. |
| OpenCTI.GroupingContexts.GroupingContextsList.description | String | Grouping context description. |

#### Command example

```!opencti-grouping-context-list```

#### Context Example

```json
{
    "OpenCTI": {
        "GroupingContexts": {
            "GroupingContextsList": [
                {
                    "description": "A set of STIX content related to a particular malware instance or family.",
                    "id": "b096d6d3-4f10-4ae9-8e5f-fa2c86d38154",
                    "name": "malware-analysis"
                },
                {
                    "description": null,
                    "id": "55c2ecec-d9ff-43ff-8722-12b6d9692570",
                    "name": "playbook"
                },
                {
                    "description": "A set of STIX content related to a particular suspicious activity event.",
                    "id": "dc87462d-ac3f-430e-8c61-d9a2ad850ace",
                    "name": "suspicious-activity"
                },
                {
                    "description": "A set of STIX content contextually related but without any precise characterization of the contextual relationship between the objects.",
                    "id": "a336d246-63b8-4551-a879-f8211bd3868b",
                    "name": "unspecified"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Grouping Contexts
>
>|Id|Name|Description|
>|---|---|---|
>| b096d6d3-4f10-4ae9-8e5f-fa2c86d38154 | malware-analysis | A set of STIX content related to a particular malware instance or family. |
>| 55c2ecec-d9ff-43ff-8722-12b6d9692570 | playbook |  |
>| dc87462d-ac3f-430e-8c61-d9a2ad850ace | suspicious-activity | A set of STIX content related to a particular suspicious activity event. |
>| a336d246-63b8-4551-a879-f8211bd3868b | unspecified | A set of STIX content contextually related but without any precise characterization of the contextual relationship between the objects. |

### opencti-report-create

***
Creates a new report.

#### Base Command

`opencti-report-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the report. | Required |
| description | Description of the report. | Optional |
| published | Published date and time (ISO 8601 format, for example, 2020-01-01T00:11:22Z). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Report.id | String | New report ID. |

#### Command example

```!opencti-report-create name="Example Report" published=2025-01-15T00:00:00.000Z```

#### Context Example

```json
{
    "OpenCTI": {
        "Report": {
            "id": "cc6e8a33-e60a-4732-8567-c1fed4038d04"
        }
    }
}
```

#### Human Readable Output

>Report created successfully. New Report id: cc6e8a33-e60a-4732-8567-c1fed4038d04.

### opencti-add-object-to-container

***
Adds an object to a container (report, grouping, case-rft, case-rfi, case-incident).

#### Base Command

`opencti-add-object-to-container`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_type | Container type. Possible values are: report, grouping, case-rft, case-rfi, case-incident. Default is grouping. | Required |
| container_id | Container ID. | Required |
| object_id | ID of the object to add to the container. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!opencti-add-object-to-container container_type=report container_id=d245afe6-56d1-4442-aef7-c42dc0e47f24 object_id=c288ff0e-4601-4e97-8b21-423dc08c1f83```

#### Human Readable Output

>Object added into report

### ip

***
Checks the reputation of an IP address in OpenCTI, using its observable and its indicator. When several indicators match the value (with its exact pattern or based on its observable), the active indicator with the highest OpenCTI score is used.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IPv4 or IPv6 addresses to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| IP.Address | String | The IP address. |
| IP.Malicious.Vendor | String | The vendor that reported the IP address as malicious. |
| IP.Malicious.Description | String | A description of why the IP address was reported as malicious. |
| IP.Relationships.Relationship | String | The name of the relationship. |
| IP.Relationships.EntityA | String | The source of the relationship. |
| IP.Relationships.EntityAType | String | The type of the source of the relationship. |
| IP.Relationships.EntityB | String | The destination of the relationship. |
| IP.Relationships.EntityBType | String | The type of the destination of the relationship. |
| OpenCTI.Indicator.id | String | ID of the OpenCTI indicator. |
| OpenCTI.Indicator.name | String | Name of the indicator. |
| OpenCTI.Indicator.description | String | Description of the indicator. |
| OpenCTI.Indicator.patternType | String | Pattern type of the indicator. |
| OpenCTI.Indicator.pattern | String | Pattern of the indicator. |
| OpenCTI.Indicator.mainObservableType | String | Main observable type of the indicator. |
| OpenCTI.Indicator.indicatorTypes | Unknown | Types of the indicator. |
| OpenCTI.Indicator.score | Number | OpenCTI score \(x_opencti_score\) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | The date and time from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | The date and time until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date and time of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date and time of the indicator. |
| OpenCTI.Indicator.createdBy | String | Author of the indicator. |
| OpenCTI.Indicator.creators | Unknown | Creators of the indicator. |
| OpenCTI.Indicator.labels | Unknown | Labels of the indicator. |
| OpenCTI.Indicator.markings | Unknown | Marking definitions of the indicator. |
| OpenCTI.Indicator.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Indicator.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Indicator.relationships.id | String | ID of the relationship. |
| OpenCTI.Indicator.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Indicator.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.relatedEntityId | String | ID of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityName | String | Name of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityType | String | Entity type of the entity related to the indicator. |
| OpenCTI.Observable.found | Boolean | Whether the observable was found in OpenCTI. |
| OpenCTI.Observable.id | String | ID of the OpenCTI observable. |
| OpenCTI.Observable.value | String | Value of the observable. |
| OpenCTI.Observable.type | String | Type of the observable. |
| OpenCTI.Observable.entityType | String | OpenCTI entity type of the observable. |
| OpenCTI.Observable.score | Number | OpenCTI score of the observable. |
| OpenCTI.Observable.description | String | Description of the observable. |
| OpenCTI.Observable.createdBy | String | Author of the observable. |
| OpenCTI.Observable.creators | Unknown | Creators of the observable. |
| OpenCTI.Observable.labels | Unknown | Labels of the observable. |
| OpenCTI.Observable.markings | Unknown | Marking definitions of the observable. |
| OpenCTI.Observable.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Observable.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Observable.relationships.id | String | ID of the relationship. |
| OpenCTI.Observable.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Observable.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Observable.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Observable.relationships.relatedEntityId | String | ID of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityName | String | Name of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityType | String | Entity type of the entity related to the observable. |
| OpenCTI.Observable.created | Date | Creation date and time of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date and time of the observable. |

#### Command example

```!ip ip=203.0.113.42```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "203.0.113.42",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "OpenCTI"
    },
    "IP": {
        "Address": "203.0.113.42",
        "Malicious": {
            "Description": "OpenCTI score: 90",
            "Vendor": "OpenCTI"
        },
        "Relationships": [
            {
                "EntityA": "203.0.113.42",
                "EntityAType": "IP",
                "EntityB": "XSOAR Docs Intrusion Set",
                "EntityBType": "Intrusion Set",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "203.0.113.42",
                "EntityAType": "IP",
                "EntityB": "XSOAR Docs Malware",
                "EntityBType": "Malware",
                "Relationship": "related-to"
            }
        ]
    },
    "OpenCTI": {
        "Indicator": {
            "confidence": 100,
            "created": "2026-11-05T15:51:10.127Z",
            "createdBy": null,
            "creators": [
                "XSOAR OpenCTI"
            ],
            "description": "Simple indicator of observable {203.0.113.42}",
            "detection": false,
            "externalReferences": null,
            "id": "545d6f4a-ed76-4e98-9fde-d213f7b93cb7",
            "indicatorTypes": null,
            "labels": null,
            "mainObservableType": "IPv4-Addr",
            "markings": null,
            "name": "203.0.113.42",
            "pattern": "[ipv4-addr:value = '203.0.113.42']",
            "patternType": "stix",
            "relationships": [
                {
                    "fromEntityType": "Indicator",
                    "fromId": "545d6f4a-ed76-4e98-9fde-d213f7b93cb7",
                    "fromName": "203.0.113.42",
                    "id": "e36eeb3a-9cba-4532-966a-afe687ada685",
                    "relatedEntityId": "ab5fdfbd-4f47-4f90-b74d-795805ee6198",
                    "relatedEntityName": "XSOAR Docs Intrusion Set",
                    "relatedEntityType": "Intrusion-Set",
                    "relationshipType": "indicates",
                    "toEntityType": "Intrusion-Set",
                    "toId": "ab5fdfbd-4f47-4f90-b74d-795805ee6198",
                    "toName": "XSOAR Docs Intrusion Set"
                }
            ],
            "revoked": false,
            "score": 90,
            "updatedAt": "2026-11-05T15:51:10.127Z",
            "validFrom": "2026-11-05T15:51:09.988Z",
            "validUntil": "2026-12-06T16:57:48.045Z"
        },
        "Observable": {
            "created": "2026-11-05T15:51:09.194Z",
            "createdBy": null,
            "creators": [
                "XSOAR OpenCTI",
                "[C] abuse-ipdb"
            ],
            "description": null,
            "entityType": "IPv4-Addr",
            "externalReferences": [
                {
                    "sourceName": "AbuseIPDB (whitelist)",
                    "url": "https://www.abuseipdb.com/check/203.0.113.42"
                }
            ],
            "found": true,
            "id": "90d8810a-0d5f-4465-8e34-8e000044e132",
            "labels": [
                "whitelist"
            ],
            "markings": null,
            "relationships": [
                {
                    "fromEntityType": "IPv4-Addr",
                    "fromId": "90d8810a-0d5f-4465-8e34-8e000044e132",
                    "fromName": "203.0.113.42",
                    "id": "2ddd220a-2d8d-42cb-9237-9859b2608d14",
                    "relatedEntityId": "dd4e190a-aa9b-490b-b0d2-8bff76bf7444",
                    "relatedEntityName": "XSOAR Docs Malware",
                    "relatedEntityType": "Malware",
                    "relationshipType": "related-to",
                    "toEntityType": "Malware",
                    "toId": "dd4e190a-aa9b-490b-b0d2-8bff76bf7444",
                    "toName": "XSOAR Docs Malware"
                }
            ],
            "score": 90,
            "type": "IP",
            "updatedAt": "2026-11-05T15:51:10.909Z",
            "value": "203.0.113.42"
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for ip 203.0.113.42
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|Observable ID|Observable Link|
>|---|---|---|---|---|---|
>| 203.0.113.42 | 90 | 545d6f4a-ed76-4e98-9fde-d213f7b93cb7 | [View in OpenCTI](https://opencti.example.com/dashboard/id/545d6f4a-ed76-4e98-9fde-d213f7b93cb7) | 90d8810a-0d5f-4465-8e34-8e000044e132 | [View in OpenCTI](https://opencti.example.com/dashboard/id/90d8810a-0d5f-4465-8e34-8e000044e132) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| 203.0.113.42 | [ipv4-addr:value = '203.0.113.42'] | 90 | 100 | 2026-11-05T15:51:09.988Z | 2026-12-06T16:57:48.045Z | false | false |
>
>### Indicator relationships
>
>|Relationship|Entity type|Entity|
>|---|---|---|
>| indicates | Intrusion-Set | [XSOAR Docs Intrusion Set](https://opencti.example.com/dashboard/id/ab5fdfbd-4f47-4f90-b74d-795805ee6198) |
>
>### Observable relationships
>
>|Relationship|Entity type|Entity|
>|---|---|---|
>| related-to | Malware | [XSOAR Docs Malware](https://opencti.example.com/dashboard/id/dd4e190a-aa9b-490b-b0d2-8bff76bf7444) |

### domain

***
Checks the reputation of a domain in OpenCTI, using its observable and its indicator. When several indicators match the value (with its exact pattern or based on its observable), the active indicator with the highest OpenCTI score is used.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| Domain.Name | String | The domain name. |
| Domain.Malicious.Vendor | String | The vendor that reported the domain as malicious. |
| Domain.Malicious.Description | String | A description of why the domain was reported as malicious. |
| Domain.Relationships.Relationship | String | The name of the relationship. |
| Domain.Relationships.EntityA | String | The source of the relationship. |
| Domain.Relationships.EntityAType | String | The type of the source of the relationship. |
| Domain.Relationships.EntityB | String | The destination of the relationship. |
| Domain.Relationships.EntityBType | String | The type of the destination of the relationship. |
| OpenCTI.Indicator.id | String | ID of the OpenCTI indicator. |
| OpenCTI.Indicator.name | String | Name of the indicator. |
| OpenCTI.Indicator.description | String | Description of the indicator. |
| OpenCTI.Indicator.patternType | String | Pattern type of the indicator. |
| OpenCTI.Indicator.pattern | String | Pattern of the indicator. |
| OpenCTI.Indicator.mainObservableType | String | Main observable type of the indicator. |
| OpenCTI.Indicator.indicatorTypes | Unknown | Types of the indicator. |
| OpenCTI.Indicator.score | Number | OpenCTI score \(x_opencti_score\) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | The date and time from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | The date and time until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date and time of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date and time of the indicator. |
| OpenCTI.Indicator.createdBy | String | Author of the indicator. |
| OpenCTI.Indicator.creators | Unknown | Creators of the indicator. |
| OpenCTI.Indicator.labels | Unknown | Labels of the indicator. |
| OpenCTI.Indicator.markings | Unknown | Marking definitions of the indicator. |
| OpenCTI.Indicator.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Indicator.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Indicator.relationships.id | String | ID of the relationship. |
| OpenCTI.Indicator.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Indicator.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.relatedEntityId | String | ID of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityName | String | Name of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityType | String | Entity type of the entity related to the indicator. |
| OpenCTI.Observable.found | Boolean | Whether the observable was found in OpenCTI. |
| OpenCTI.Observable.id | String | ID of the OpenCTI observable. |
| OpenCTI.Observable.value | String | Value of the observable. |
| OpenCTI.Observable.type | String | Type of the observable. |
| OpenCTI.Observable.entityType | String | OpenCTI entity type of the observable. |
| OpenCTI.Observable.score | Number | OpenCTI score of the observable. |
| OpenCTI.Observable.description | String | Description of the observable. |
| OpenCTI.Observable.createdBy | String | Author of the observable. |
| OpenCTI.Observable.creators | Unknown | Creators of the observable. |
| OpenCTI.Observable.labels | Unknown | Labels of the observable. |
| OpenCTI.Observable.markings | Unknown | Marking definitions of the observable. |
| OpenCTI.Observable.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Observable.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Observable.relationships.id | String | ID of the relationship. |
| OpenCTI.Observable.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Observable.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Observable.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Observable.relationships.relatedEntityId | String | ID of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityName | String | Name of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityType | String | Entity type of the entity related to the observable. |
| OpenCTI.Observable.created | Date | Creation date and time of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date and time of the observable. |

#### Command example

```!domain domain=suspicious.example.com```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "suspicious.example.com",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "OpenCTI"
    },
    "Domain": {
        "Name": "suspicious.example.com"
    },
    "OpenCTI": {
        "Indicator": {
            "confidence": 50,
            "created": "2026-11-05T15:51:17.535Z",
            "createdBy": null,
            "creators": [
                "XSOAR OpenCTI"
            ],
            "description": null,
            "detection": false,
            "externalReferences": null,
            "id": "7896fcbf-170e-42bf-a02e-ad5e66a3c7dc",
            "indicatorTypes": null,
            "labels": null,
            "mainObservableType": "Domain-Name",
            "markings": null,
            "name": "suspicious.example.com",
            "pattern": "[domain-name:value = 'suspicious.example.com']",
            "patternType": "stix",
            "relationships": null,
            "revoked": false,
            "score": 60,
            "updatedAt": "2026-11-05T15:51:53.714Z",
            "validFrom": "2026-11-05T00:00:00.000Z",
            "validUntil": "2027-09-01T15:51:53.585Z"
        },
        "Observable": {
            "found": false,
            "type": "domain",
            "value": "suspicious.example.com"
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for domain suspicious.example.com
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|
>|---|---|---|---|
>| suspicious.example.com | 60 | 7896fcbf-170e-42bf-a02e-ad5e66a3c7dc | [View in OpenCTI](https://opencti.example.com/dashboard/id/7896fcbf-170e-42bf-a02e-ad5e66a3c7dc) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| suspicious.example.com | [domain-name:value = 'suspicious.example.com'] | 60 | 50 | 2026-11-05T00:00:00.000Z | 2027-09-01T15:51:53.585Z | false | false |

### email

***
Checks the reputation of an email address in OpenCTI, using its observable and its indicator. When several indicators match the value (with its exact pattern or based on its observable), the active indicator with the highest OpenCTI score is used.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | A comma-separated list of email addresses to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| Account.Email.Address | String | The email address. |
| Account.Relationships.Relationship | String | The name of the relationship. |
| Account.Relationships.EntityA | String | The source of the relationship. |
| Account.Relationships.EntityAType | String | The type of the source of the relationship. |
| Account.Relationships.EntityB | String | The destination of the relationship. |
| Account.Relationships.EntityBType | String | The type of the destination of the relationship. |
| OpenCTI.Indicator.id | String | ID of the OpenCTI indicator. |
| OpenCTI.Indicator.name | String | Name of the indicator. |
| OpenCTI.Indicator.description | String | Description of the indicator. |
| OpenCTI.Indicator.patternType | String | Pattern type of the indicator. |
| OpenCTI.Indicator.pattern | String | Pattern of the indicator. |
| OpenCTI.Indicator.mainObservableType | String | Main observable type of the indicator. |
| OpenCTI.Indicator.indicatorTypes | Unknown | Types of the indicator. |
| OpenCTI.Indicator.score | Number | OpenCTI score \(x_opencti_score\) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | The date and time from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | The date and time until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date and time of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date and time of the indicator. |
| OpenCTI.Indicator.createdBy | String | Author of the indicator. |
| OpenCTI.Indicator.creators | Unknown | Creators of the indicator. |
| OpenCTI.Indicator.labels | Unknown | Labels of the indicator. |
| OpenCTI.Indicator.markings | Unknown | Marking definitions of the indicator. |
| OpenCTI.Indicator.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Indicator.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Indicator.relationships.id | String | ID of the relationship. |
| OpenCTI.Indicator.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Indicator.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.relatedEntityId | String | ID of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityName | String | Name of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityType | String | Entity type of the entity related to the indicator. |
| OpenCTI.Observable.found | Boolean | Whether the observable was found in OpenCTI. |
| OpenCTI.Observable.id | String | ID of the OpenCTI observable. |
| OpenCTI.Observable.value | String | Value of the observable. |
| OpenCTI.Observable.type | String | Type of the observable. |
| OpenCTI.Observable.entityType | String | OpenCTI entity type of the observable. |
| OpenCTI.Observable.score | Number | OpenCTI score of the observable. |
| OpenCTI.Observable.description | String | Description of the observable. |
| OpenCTI.Observable.createdBy | String | Author of the observable. |
| OpenCTI.Observable.creators | Unknown | Creators of the observable. |
| OpenCTI.Observable.labels | Unknown | Labels of the observable. |
| OpenCTI.Observable.markings | Unknown | Marking definitions of the observable. |
| OpenCTI.Observable.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Observable.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Observable.relationships.id | String | ID of the relationship. |
| OpenCTI.Observable.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Observable.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Observable.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Observable.relationships.relatedEntityId | String | ID of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityName | String | Name of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityType | String | Entity type of the entity related to the observable. |
| OpenCTI.Observable.created | Date | Creation date and time of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date and time of the observable. |

#### Command example

```!email email=phishing@example.com```

#### Context Example

```json
{
    "Account": {
        "Email": {
            "Address": "phishing@example.com"
        }
    },
    "DBotScore": {
        "Indicator": "phishing@example.com",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "email",
        "Vendor": "OpenCTI"
    },
    "OpenCTI": {
        "Indicator": {
            "confidence": 100,
            "created": "2026-11-05T15:51:13.992Z",
            "createdBy": null,
            "creators": [
                "XSOAR OpenCTI"
            ],
            "description": "Simple indicator of observable {phishing@example.com}",
            "detection": false,
            "externalReferences": null,
            "id": "707aee5e-aeec-4bcb-abab-a29aa65714d3",
            "indicatorTypes": null,
            "labels": null,
            "mainObservableType": "Email-Addr",
            "markings": null,
            "name": "phishing@example.com",
            "pattern": "[email-addr:value = 'phishing@example.com']",
            "patternType": "stix",
            "relationships": null,
            "revoked": false,
            "score": 90,
            "updatedAt": "2026-11-05T15:51:13.992Z",
            "validFrom": "2026-11-05T15:51:13.859Z",
            "validUntil": "2027-11-01T15:38:01.217Z"
        },
        "Observable": {
            "created": "2026-11-05T15:51:13.294Z",
            "createdBy": null,
            "creators": [
                "XSOAR OpenCTI"
            ],
            "description": null,
            "entityType": "Email-Addr",
            "externalReferences": null,
            "found": true,
            "id": "e3fe936b-ad64-487b-bbb0-021b36e3a4fe",
            "labels": null,
            "markings": null,
            "relationships": null,
            "score": 90,
            "type": "Email",
            "updatedAt": "2026-11-05T15:51:13.294Z",
            "value": "phishing@example.com"
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for email phishing@example.com
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|Observable ID|Observable Link|
>|---|---|---|---|---|---|
>| phishing@example.com | 90 | 707aee5e-aeec-4bcb-abab-a29aa65714d3 | [View in OpenCTI](https://opencti.example.com/dashboard/id/707aee5e-aeec-4bcb-abab-a29aa65714d3) | e3fe936b-ad64-487b-bbb0-021b36e3a4fe | [View in OpenCTI](https://opencti.example.com/dashboard/id/e3fe936b-ad64-487b-bbb0-021b36e3a4fe) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| phishing@example.com | [email-addr:value = 'phishing@example.com'] | 90 | 100 | 2026-11-05T15:51:13.859Z | 2027-11-01T15:38:01.217Z | false | false |

### url

***
Checks the reputation of a URL in OpenCTI, using its observable and its indicator. When several indicators match the value (with its exact pattern or based on its observable), the active indicator with the highest OpenCTI score is used.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| URL.Data | String | The URL. |
| URL.Malicious.Vendor | String | The vendor that reported the URL as malicious. |
| URL.Malicious.Description | String | A description of why the URL was reported as malicious. |
| URL.Relationships.Relationship | String | The name of the relationship. |
| URL.Relationships.EntityA | String | The source of the relationship. |
| URL.Relationships.EntityAType | String | The type of the source of the relationship. |
| URL.Relationships.EntityB | String | The destination of the relationship. |
| URL.Relationships.EntityBType | String | The type of the destination of the relationship. |
| OpenCTI.Indicator.id | String | ID of the OpenCTI indicator. |
| OpenCTI.Indicator.name | String | Name of the indicator. |
| OpenCTI.Indicator.description | String | Description of the indicator. |
| OpenCTI.Indicator.patternType | String | Pattern type of the indicator. |
| OpenCTI.Indicator.pattern | String | Pattern of the indicator. |
| OpenCTI.Indicator.mainObservableType | String | Main observable type of the indicator. |
| OpenCTI.Indicator.indicatorTypes | Unknown | Types of the indicator. |
| OpenCTI.Indicator.score | Number | OpenCTI score \(x_opencti_score\) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | The date and time from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | The date and time until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date and time of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date and time of the indicator. |
| OpenCTI.Indicator.createdBy | String | Author of the indicator. |
| OpenCTI.Indicator.creators | Unknown | Creators of the indicator. |
| OpenCTI.Indicator.labels | Unknown | Labels of the indicator. |
| OpenCTI.Indicator.markings | Unknown | Marking definitions of the indicator. |
| OpenCTI.Indicator.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Indicator.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Indicator.relationships.id | String | ID of the relationship. |
| OpenCTI.Indicator.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Indicator.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.relatedEntityId | String | ID of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityName | String | Name of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityType | String | Entity type of the entity related to the indicator. |
| OpenCTI.Observable.found | Boolean | Whether the observable was found in OpenCTI. |
| OpenCTI.Observable.id | String | ID of the OpenCTI observable. |
| OpenCTI.Observable.value | String | Value of the observable. |
| OpenCTI.Observable.type | String | Type of the observable. |
| OpenCTI.Observable.entityType | String | OpenCTI entity type of the observable. |
| OpenCTI.Observable.score | Number | OpenCTI score of the observable. |
| OpenCTI.Observable.description | String | Description of the observable. |
| OpenCTI.Observable.createdBy | String | Author of the observable. |
| OpenCTI.Observable.creators | Unknown | Creators of the observable. |
| OpenCTI.Observable.labels | Unknown | Labels of the observable. |
| OpenCTI.Observable.markings | Unknown | Marking definitions of the observable. |
| OpenCTI.Observable.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Observable.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Observable.relationships.id | String | ID of the relationship. |
| OpenCTI.Observable.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Observable.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Observable.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Observable.relationships.relatedEntityId | String | ID of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityName | String | Name of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityType | String | Entity type of the entity related to the observable. |
| OpenCTI.Observable.created | Date | Creation date and time of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date and time of the observable. |

#### Command example

```!url url=https://malicious.example.com/payload```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "https://malicious.example.com/payload",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "url",
        "Vendor": "OpenCTI"
    },
    "OpenCTI": {
        "Indicator": {
            "confidence": 100,
            "created": "2026-11-05T15:51:11.849Z",
            "createdBy": null,
            "creators": [
                "XSOAR OpenCTI"
            ],
            "description": "Simple indicator of observable {https://malicious.example.com/payload}",
            "detection": false,
            "externalReferences": null,
            "id": "4c1afb07-e24b-4de3-9334-aeddfd435fb2",
            "indicatorTypes": null,
            "labels": null,
            "mainObservableType": "Url",
            "markings": null,
            "name": "https://malicious.example.com/payload",
            "pattern": "[url:value = 'https://malicious.example.com/payload']",
            "patternType": "stix",
            "relationships": null,
            "revoked": false,
            "score": 90,
            "updatedAt": "2026-11-05T15:51:11.849Z",
            "validFrom": "2026-11-05T15:51:11.694Z",
            "validUntil": "2026-12-06T16:57:49.751Z"
        },
        "Observable": {
            "created": "2026-11-05T15:51:11.545Z",
            "createdBy": null,
            "creators": [
                "XSOAR OpenCTI"
            ],
            "description": null,
            "entityType": "Url",
            "externalReferences": null,
            "found": true,
            "id": "7267c66a-b1c3-4bda-b33a-2b1546f9b00e",
            "labels": null,
            "markings": null,
            "relationships": null,
            "score": 90,
            "type": "URL",
            "updatedAt": "2026-11-05T15:51:11.545Z",
            "value": "https://malicious.example.com/payload"
        }
    },
    "URL": {
        "Data": "https://malicious.example.com/payload",
        "Malicious": {
            "Description": "OpenCTI score: 90",
            "Vendor": "OpenCTI"
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for url https:<span>//</span>malicious.example.com/payload
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|Observable ID|Observable Link|
>|---|---|---|---|---|---|
>| https:<span>//</span>malicious.example.com/payload | 90 | 4c1afb07-e24b-4de3-9334-aeddfd435fb2 | [View in OpenCTI](https://opencti.example.com/dashboard/id/4c1afb07-e24b-4de3-9334-aeddfd435fb2) | 7267c66a-b1c3-4bda-b33a-2b1546f9b00e | [View in OpenCTI](https://opencti.example.com/dashboard/id/7267c66a-b1c3-4bda-b33a-2b1546f9b00e) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| https:<span>//</span>malicious.example.com/payload | [url:value = 'https:<span>//</span>malicious.example.com/payload'] | 90 | 100 | 2026-11-05T15:51:11.694Z | 2026-12-06T16:57:49.751Z | false | false |

### file

***
Checks the reputation of a file hash in OpenCTI, using its observable and its indicator. When several indicators match the value (with its exact pattern or based on its observable), the active indicator with the highest OpenCTI score is used.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of MD5, SHA-1 or SHA-256 file hashes to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| File.MD5 | String | The MD5 hash of the file. |
| File.SHA1 | String | The SHA-1 hash of the file. |
| File.SHA256 | String | The SHA-256 hash of the file. |
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. |
| File.Malicious.Description | String | A description of why the file was reported as malicious. |
| File.Relationships.Relationship | String | The name of the relationship. |
| File.Relationships.EntityA | String | The source of the relationship. |
| File.Relationships.EntityAType | String | The type of the source of the relationship. |
| File.Relationships.EntityB | String | The destination of the relationship. |
| File.Relationships.EntityBType | String | The type of the destination of the relationship. |
| OpenCTI.Indicator.id | String | ID of the OpenCTI indicator. |
| OpenCTI.Indicator.name | String | Name of the indicator. |
| OpenCTI.Indicator.description | String | Description of the indicator. |
| OpenCTI.Indicator.patternType | String | Pattern type of the indicator. |
| OpenCTI.Indicator.pattern | String | Pattern of the indicator. |
| OpenCTI.Indicator.mainObservableType | String | Main observable type of the indicator. |
| OpenCTI.Indicator.indicatorTypes | Unknown | Types of the indicator. |
| OpenCTI.Indicator.score | Number | OpenCTI score \(x_opencti_score\) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | The date and time from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | The date and time until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date and time of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date and time of the indicator. |
| OpenCTI.Indicator.createdBy | String | Author of the indicator. |
| OpenCTI.Indicator.creators | Unknown | Creators of the indicator. |
| OpenCTI.Indicator.labels | Unknown | Labels of the indicator. |
| OpenCTI.Indicator.markings | Unknown | Marking definitions of the indicator. |
| OpenCTI.Indicator.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Indicator.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Indicator.relationships.id | String | ID of the relationship. |
| OpenCTI.Indicator.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Indicator.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Indicator.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Indicator.relationships.relatedEntityId | String | ID of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityName | String | Name of the entity related to the indicator. |
| OpenCTI.Indicator.relationships.relatedEntityType | String | Entity type of the entity related to the indicator. |
| OpenCTI.Observable.found | Boolean | Whether the observable was found in OpenCTI. |
| OpenCTI.Observable.id | String | ID of the OpenCTI observable. |
| OpenCTI.Observable.value | String | Value of the observable. |
| OpenCTI.Observable.type | String | Type of the observable. |
| OpenCTI.Observable.entityType | String | OpenCTI entity type of the observable. |
| OpenCTI.Observable.score | Number | OpenCTI score of the observable. |
| OpenCTI.Observable.description | String | Description of the observable. |
| OpenCTI.Observable.createdBy | String | Author of the observable. |
| OpenCTI.Observable.creators | Unknown | Creators of the observable. |
| OpenCTI.Observable.labels | Unknown | Labels of the observable. |
| OpenCTI.Observable.markings | Unknown | Marking definitions of the observable. |
| OpenCTI.Observable.externalReferences.sourceName | String | Source name of the external reference. |
| OpenCTI.Observable.externalReferences.url | String | URL of the external reference. |
| OpenCTI.Observable.relationships.id | String | ID of the relationship. |
| OpenCTI.Observable.relationships.relationshipType | String | Type of the relationship. |
| OpenCTI.Observable.relationships.fromId | String | ID of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromName | String | Name of the source entity of the relationship. |
| OpenCTI.Observable.relationships.fromEntityType | String | Entity type of the source entity of the relationship. |
| OpenCTI.Observable.relationships.toId | String | ID of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toName | String | Name of the target entity of the relationship. |
| OpenCTI.Observable.relationships.toEntityType | String | Entity type of the target entity of the relationship. |
| OpenCTI.Observable.relationships.relatedEntityId | String | ID of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityName | String | Name of the entity related to the observable. |
| OpenCTI.Observable.relationships.relatedEntityType | String | Entity type of the entity related to the observable. |
| OpenCTI.Observable.created | Date | Creation date and time of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date and time of the observable. |

#### Command example

```!file file=41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "OpenCTI"
    },
    "File": {
        "Hashes": [
            {
                "type": "SHA256",
                "value": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84"
            }
        ],
        "Malicious": {
            "Description": "OpenCTI score: 90",
            "Vendor": "OpenCTI"
        },
        "SHA256": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84"
    },
    "OpenCTI": {
        "Indicator": {
            "confidence": 100,
            "created": "2026-11-05T15:51:15.984Z",
            "createdBy": null,
            "creators": [
                "XSOAR OpenCTI"
            ],
            "description": "Simple indicator of observable {41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84}",
            "detection": false,
            "externalReferences": null,
            "id": "e08ba4e6-500d-4c69-85fa-07c5fffe5f3f",
            "indicatorTypes": null,
            "labels": null,
            "mainObservableType": "StixFile",
            "markings": null,
            "name": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84",
            "pattern": "[file:hashes.'SHA-256' = '41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84']",
            "patternType": "stix",
            "relationships": null,
            "revoked": false,
            "score": 90,
            "updatedAt": "2026-11-05T15:51:15.984Z",
            "validFrom": "2026-11-05T15:51:15.859Z",
            "validUntil": "2027-11-07T13:03:03.158Z"
        },
        "Observable": {
            "created": "2026-11-05T15:51:15.309Z",
            "createdBy": null,
            "creators": [
                "XSOAR OpenCTI"
            ],
            "description": null,
            "entityType": "StixFile",
            "externalReferences": null,
            "found": true,
            "id": "4dda34c3-493f-4f7d-b636-ffc3263ebf02",
            "labels": null,
            "markings": null,
            "relationships": null,
            "score": 90,
            "type": "File",
            "updatedAt": "2026-11-05T15:51:15.309Z",
            "value": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84"
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for file 41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|Observable ID|Observable Link|
>|---|---|---|---|---|---|
>| 41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84 | 90 | e08ba4e6-500d-4c69-85fa-07c5fffe5f3f | [View in OpenCTI](https://opencti.example.com/dashboard/id/e08ba4e6-500d-4c69-85fa-07c5fffe5f3f) | 4dda34c3-493f-4f7d-b636-ffc3263ebf02 | [View in OpenCTI](https://opencti.example.com/dashboard/id/4dda34c3-493f-4f7d-b636-ffc3263ebf02) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| 41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84 | [file:hashes.'SHA-256' = '41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84'] | 90 | 100 | 2026-11-05T15:51:15.859Z | 2027-11-07T13:03:03.158Z | false | false |
