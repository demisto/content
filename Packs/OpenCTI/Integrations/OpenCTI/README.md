Manages indicators from OpenCTI.  
This integration was tested with version 6.9.X of OpenCTI.

## Configure OpenCTI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpenCTI.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Required** |
   | --- | --- |
   | Base URL | True |
   | API Key (leave empty. Fill in the API key in the password field.) | False |
   | Trust any certificate (not secure) | False |
   | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

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

#### Command Example

```!opencti-indicator-field-add id=33bd535b-fa1c-41e2-a6f9-80d82dd29a9b field=label value=07cfae2d-6cc9-42c5-9fd0-32eff8142404```

#### Human Readable Output

>Added label successfully.

### opencti-indicator-field-remove

***
Remove indicator field value. Fields which values can be removed are marking definition and label.

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
| create_observables | Create OpenCTI observable related with the OpenCTI indicator created. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicator.id | string | New Indicator ID. |

### opencti-organization-list

***
Get a list of all organizations in OpenCTI.

#### Base Command

`opencti-organization-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of organizations to return per fetch. Default is 50. Maximum value is 200. | Optional |
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.Organizations.organizationsLastRun context path. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Organizations.OrganizationsList.id | String | Organization ID. |
| OpenCTI.Organizations.OrganizationsList.name | String | Organization name. |
| OpenCTI.Organizations.organizationsLastRun | String | The last ID of the previous fetch to use for pagination. |

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
>
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
>
>|Value|Id|
>|---|---|
>| TLP:GREEN | dc911977-796a-4d96-95e4-615bd1c41263 |
>| TLP:AMBER | 9128e411-c759-4af0-aeb0-b65f12082648 |
>
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
| OpenCTI.Relationship.id | unknown | New Relationship ID. |
| OpenCTI.Relationship.relationshipType | unknown | New Relationship Type. |

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

### opencti-incident-create

***
Create new incident.

#### Base Command

`opencti-incident-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Incident name. | Required |
| incident_type | Incident Type name. Use opencti-incident-types-list to find all incident types in OpenCTI. | Optional |
| confidence | Incident Confidence Number. Values range is 0 - 100. Default value is 50. | Optional |
| severity | Incident severity. Possible values are: low, medium, high, critical. | Optional |
| description | Incident description. | Optional |
| source | Incident Source. | Optional |
| objective | Incident objective. | Optional |
| created_by | Organization ID. Use opencti-organization-list to find all organization IDs in OpenCTI, or use opencti-organization-create to create a new organization ID. | Optional |
| first_seen | Incident First seen. YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| last_seen | Incident Last seen. YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| label_id | Incident label ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. | Optional |
| marking_id | Observable marking definition ID. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Optional |
| external_references_id | External references URL. Use opencti-external-reference-create to create a new external reference. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Incident.id | String | New Incident ID. |

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
| OpenCTI.Indicator.id | string | New Indicator ID. |
| OpenCTI.Indicator.name | string | Name of the updated indicator. |
| OpenCTI.Indicator.validFrom | string | The valid-from date of the updated indicator. |
| OpenCTI.Indicator.validUntil | string | The valid-until date of the updated indicator. |

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
| create_indicator | Create OpenCTI indicator related with the OpenCTI observable created. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Observable.id | String | New observable ID. |
| OpenCTI.Observable.value | String | New observable value. |
| OpenCTI.Observable.type | String | New observable type. |

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

### opencti-incident-response-create

***
Create new incident response.

#### Base Command

`opencti-incident-response-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Incident Response name. | Required |
| incident_response_type | Incident Response type name. Use opencti-incident-types-list to find all incident types in OpenCTI. | Optional |
| severity | Incident Response severity. Possible values are: low, medium, high, critical. | Optional |
| priority | Incident Response priority. Possible values are: P1, P2, P3, P4. | Optional |
| description | Incident Response description. | Optional |
| created_by | Organization ID. Use opencti-organization-list to find all organization IDs in OpenCTI, or use opencti-organization-create to create a new organization ID. | Optional |
| incident_response_date | Incident Response date. YYYY-MM-DDThh:mm:ss.sssZ. | Optional |
| label_id | Incident Response label ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. | Optional |
| marking_id | Incident Response marking definition ID. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Optional |
| external_references_id | External references URL. Use opencti-external-reference-create to create a new external reference. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.IncidentResponse.id | String | New incident response ID. |

### opencti-malware-create

***
Create a new malware.

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

### opencti-vulnerability-create

***
Create a new vulnerability.

#### Base Command

`opencti-vulnerability-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the vulnerability (e.g., CVE-2025-0001). | Required |
| description | Description of the vulnerability. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Vulnerability.id | String | New vulnerability ID. |

### opencti-intrusion-set-create

***
Create a new intrusion-set.

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
| OpenCTI.IntrusionSet.id | String | New intrusion-set ID. |

### opencti-threat-actor-group-create

***
Create a new threat actor group.

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

### opencti-campaign-create

***
Create a new campaign.

#### Base Command

`opencti-campaign-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the campaign. | Required |
| description | Description of the campaign. | Optional |
| first_seen | First seen date (ISO 8601 format). | Optional |
| last_seen | Last seen date (ISO 8601 format). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.campaign.id | String | New campaign ID. |

### opencti-grouping-create

***
Create a new grouping.

#### Base Command

`opencti-grouping-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the grouping. | Required |
| description | Description of the grouping. | Optional |
| context | Context of the grouping. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.grouping.id | String | New grouping ID. |

### opencti-report-create

***
Create a new report.

#### Base Command

`opencti-report-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the report. | Required |
| description | Description of the report. | Optional |
| published | Published date (ISO 8601 format). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.report.id | String | New report ID. |

### opencti-add-object-to-container

***
Add object to container (report, grouping, case-rft, case-rfi, case-incident).

#### Base Command

`opencti-add-object-to-container`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_type | Container type. Possible values are: report, grouping, case-rft, case-rfi, case-incident. Default is grouping. | Required |
| container_id | Container Id. | Required |
| object_id | Id of the object to add in the container. | Required |

#### Context Output

There is no context output for this command.
