Manages indicators from OpenCTI.  
This integration was tested with OpenCTI 6.9.0 and 7.261.X.

## Configure OpenCTI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpenCTI.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Description** | **Required** |
   | --- | --- | --- |
   | Base URL | The URL of the OpenCTI platform, for example https://opencti.example.com. | True |
   | API Key (leave empty. Fill in the API key in the password field.) | The API key of the OpenCTI user, available in the API access section of the user profile in OpenCTI. | False |
   | Trust any certificate (not secure) | Whether to skip the verification of the SSL certificate of the OpenCTI platform. | False |
   | Use system proxy settings | Whether to use the system proxy settings to connect to the OpenCTI platform. | False |
   | Redirect stdout | Used for troubleshooting purposes. | False |
   | Source Reliability | The reliability of the source providing the intelligence data. | False |
   | Suspicious score threshold (0-100) | Used by the ip, domain, email, url and file commands. An indicator whose OpenCTI score (x_opencti_score) is above this threshold and not above the malicious score threshold is suspicious. An indicator whose score is not above this threshold is good. A value unknown to OpenCTI is unknown. | False |
   | Malicious score threshold (0-100) | Used by the ip, domain, email, url and file commands. An indicator whose OpenCTI score (x_opencti_score) is above this threshold is malicious. Must not be below the suspicious score threshold. | False |
   | Create relationships | Whether to create relationships between indicators as part of enrichment. | False |

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

#### Command Example

```!opencti-observable-field-update id=a6b0bb74-fa60-46b9-ae12-08a82f1608c0 field=score value=80```

#### Context Example

```json
{
    "OpenCTI": {
        "Observable": {
            "id": "a6b0bb74-fa60-46b9-ae12-08a82f1608c0"
        }
    }
}
```

#### Human Readable Output

>Observable a6b0bb74-fa60-46b9-ae12-08a82f1608c0 updated successfully.

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
Create a new incident response.

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
| incident_response_date | Incident Response date (ISO 8601 format, e.g., 2020-01-01T00:11:22.000Z). | Optional |
| label_id | Incident Response label ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. | Optional |
| marking_id | Incident Response marking definition ID. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Optional |
| external_references_id | External references URL. Use opencti-external-reference-create to create a new external reference. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.IncidentResponse.id | String | New incident response ID. |

#### Command Example

```!opencti-incident-response-create name="Example Incident Response" severity=high priority=P2 description="Incident response created from Cortex XSOAR." incident_response_date=2025-01-15T09:30:00.000Z```

#### Context Example

```json
{
    "OpenCTI": {
        "IncidentResponse": {
            "id": "1dd4400b-baa9-4c26-a623-063402c62ec5"
        }
    }
}
```

#### Human Readable Output

>Incident response created successfully. New Incident Response id: 1dd4400b-baa9-4c26-a623-063402c62ec5.

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

#### Command Example

```!opencti-malware-create name="Example Malware" malware_types=ransomware,worm is_family=true```

#### Context Example

```json
{
    "OpenCTI": {
        "Malware": {
            "id": "0e6fcea0-670c-473e-ad53-cf3f80dd7764"
        }
    }
}
```

#### Human Readable Output

>Malware created successfully. New Malware id: 0e6fcea0-670c-473e-ad53-cf3f80dd7764.

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

#### Command Example

```!opencti-vulnerability-create name=CVE-2025-0001 description="Vulnerability created from Cortex XSOAR."```

#### Context Example

```json
{
    "OpenCTI": {
        "Vulnerability": {
            "id": "74d6e30e-c856-48be-9a44-dfcc171dbfb6"
        }
    }
}
```

#### Human Readable Output

>Vulnerability created successfully. New Vulnerability id: 74d6e30e-c856-48be-9a44-dfcc171dbfb6.

### opencti-intrusion-set-create

***
Create a new intrusion set.

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

#### Command Example

```!opencti-intrusion-set-create name="Example Intrusion Set"```

#### Context Example

```json
{
    "OpenCTI": {
        "IntrusionSet": {
            "id": "c12eb4b3-034b-49a4-b5f1-98053f950ada"
        }
    }
}
```

#### Human Readable Output

>Intrusion set created successfully. New Intrusion Set id: c12eb4b3-034b-49a4-b5f1-98053f950ada.

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

#### Command Example

```!opencti-threat-actor-group-create name="Example Threat Actor Group"```

#### Context Example

```json
{
    "OpenCTI": {
        "ThreatActorGroup": {
            "id": "a5310634-4b9f-48be-8253-bfe8fec9d1be"
        }
    }
}
```

#### Human Readable Output

>Threat Actor Group created successfully. New Threat Actor Group id: a5310634-4b9f-48be-8253-bfe8fec9d1be.

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
| first_seen | First seen date (ISO 8601 format, e.g., 2020-01-01T00:11:22Z). | Optional |
| last_seen | Last seen date (ISO 8601 format, e.g., 2020-01-01T00:11:22Z). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Campaign.id | String | New campaign ID. |

#### Command Example

```!opencti-campaign-create name="Example Campaign" first_seen=2025-01-01T00:00:00Z last_seen=2025-06-30T00:00:00Z```

#### Context Example

```json
{
    "OpenCTI": {
        "Campaign": {
            "id": "64a1bfa3-ef8a-43ab-b9af-15072287c6a2"
        }
    }
}
```

#### Human Readable Output

>Campaign created successfully. New Campaign id: 64a1bfa3-ef8a-43ab-b9af-15072287c6a2.

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
| OpenCTI.Grouping.id | String | New grouping ID. |

#### Command Example

```!opencti-grouping-create name="Example Grouping" context=suspicious-activity```

#### Context Example

```json
{
    "OpenCTI": {
        "Grouping": {
            "id": "3dd62358-879d-470f-bb34-b8eb76cd3eac"
        }
    }
}
```

#### Human Readable Output

>Grouping created successfully. New Grouping id: 3dd62358-879d-470f-bb34-b8eb76cd3eac.

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
| published | Published date (ISO 8601 format, e.g., 2020-01-01T00:11:22Z). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Report.id | String | New report ID. |

#### Command Example

```!opencti-report-create name="Example Report" published=2025-01-15T00:00:00.000Z```

#### Context Example

```json
{
    "OpenCTI": {
        "Report": {
            "id": "253e4a59-6e61-4409-a2cb-ecefd5105383"
        }
    }
}
```

#### Human Readable Output

>Report created successfully. New Report id: 253e4a59-6e61-4409-a2cb-ecefd5105383.

### opencti-add-object-to-container

***
Add an object to a container (report, grouping, case-rft, case-rfi, case-incident).

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

#### Command Example

```!opencti-add-object-to-container container_type=report container_id=253e4a59-6e61-4409-a2cb-ecefd5105383 object_id=0e6fcea0-670c-473e-ad53-cf3f80dd7764```

#### Human Readable Output

>Object added into report

### ip

***
Checks the reputation of an IP address in OpenCTI, using its observable and its indicator.

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
| OpenCTI.Indicator.score | Number | OpenCTI score (x_opencti_score) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | Date from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | Date until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date of the indicator. |
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
| OpenCTI.Observable.created | Date | Creation date of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date of the observable. |

#### Command Example

```!ip ip=203.0.113.42```

#### Context Example

```json
{
    "IP": {
        "Address": "203.0.113.42",
        "Malicious": {
            "Vendor": "OpenCTI",
            "Description": "OpenCTI score: 90"
        },
        "Relationships": [
            {
                "Relationship": "indicator-of",
                "EntityA": "203.0.113.42",
                "EntityAType": "IP",
                "EntityB": "Example Intrusion Set",
                "EntityBType": "Intrusion Set"
            },
            {
                "Relationship": "related-to",
                "EntityA": "203.0.113.42",
                "EntityAType": "IP",
                "EntityB": "Example Malware",
                "EntityBType": "Malware"
            }
        ]
    },
    "DBotScore": {
        "Indicator": "203.0.113.42",
        "Type": "ip",
        "Vendor": "OpenCTI",
        "Score": 3,
        "Reliability": "B - Usually reliable"
    },
    "OpenCTI": {
        "Observable": {
            "found": true,
            "id": "15fee5d7-fb09-409b-8b2a-70954d9116d3",
            "value": "203.0.113.42",
            "type": "IP",
            "entityType": "IPv4-Addr",
            "score": 90,
            "description": null,
            "createdBy": null,
            "creators": [
                "admin"
            ],
            "labels": [],
            "markings": [],
            "externalReferences": [],
            "relationships": [
                {
                    "id": "fa45450f-7ae3-438e-8785-2c16058a486d",
                    "relationshipType": "related-to",
                    "fromId": "15fee5d7-fb09-409b-8b2a-70954d9116d3",
                    "fromName": "203.0.113.42",
                    "fromEntityType": "IPv4-Addr",
                    "toId": "0e6fcea0-670c-473e-ad53-cf3f80dd7764",
                    "toName": "Example Malware",
                    "toEntityType": "Malware",
                    "relatedEntityId": "0e6fcea0-670c-473e-ad53-cf3f80dd7764",
                    "relatedEntityName": "Example Malware",
                    "relatedEntityType": "Malware"
                }
            ],
            "created": "2026-10-19T21:23:55.114Z",
            "updatedAt": "2026-10-19T21:23:55.114Z"
        },
        "Indicator": {
            "id": "ca6177b2-152f-42ab-9c37-ba9bea0dbce7",
            "name": "203.0.113.42",
            "description": "Simple indicator of observable {203.0.113.42}",
            "patternType": "stix",
            "pattern": "[ipv4-addr:value = '203.0.113.42']",
            "mainObservableType": "IPv4-Addr",
            "indicatorTypes": [],
            "score": 90,
            "confidence": 100,
            "validFrom": "2026-10-19T21:23:55.159Z",
            "validUntil": "2026-11-19T22:30:33.216Z",
            "revoked": false,
            "detection": false,
            "created": "2026-10-19T21:23:55.201Z",
            "updatedAt": "2026-10-19T21:23:55.201Z",
            "createdBy": null,
            "creators": [
                "admin"
            ],
            "labels": [],
            "markings": [],
            "externalReferences": [],
            "relationships": [
                {
                    "id": "38f027dc-fde7-4dff-9218-ff0034d6802b",
                    "relationshipType": "indicates",
                    "fromId": "ca6177b2-152f-42ab-9c37-ba9bea0dbce7",
                    "fromName": "203.0.113.42",
                    "fromEntityType": "Indicator",
                    "toId": "c12eb4b3-034b-49a4-b5f1-98053f950ada",
                    "toName": "Example Intrusion Set",
                    "toEntityType": "Intrusion-Set",
                    "relatedEntityId": "c12eb4b3-034b-49a4-b5f1-98053f950ada",
                    "relatedEntityName": "Example Intrusion Set",
                    "relatedEntityType": "Intrusion-Set"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for ip 203.0.113.42
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|Observable ID|Observable Link|
>|---|---|---|---|---|---|
>| 203.0.113.42 | 90 | ca6177b2-152f-42ab-9c37-ba9bea0dbce7 | [View in OpenCTI](https://opencti.example.com/dashboard/id/ca6177b2-152f-42ab-9c37-ba9bea0dbce7) | 15fee5d7-fb09-409b-8b2a-70954d9116d3 | [View in OpenCTI](https://opencti.example.com/dashboard/id/15fee5d7-fb09-409b-8b2a-70954d9116d3) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| 203.0.113.42 | [ipv4-addr:value = '203.0.113.42'] | 90 | 100 | 2026-10-19T21:23:55.159Z | 2026-11-19T22:30:33.216Z | false | false |
>
>### Indicator relationships
>
>|Relationship|Entity type|Entity|
>|---|---|---|
>| indicates | Intrusion-Set | [Example Intrusion Set](https://opencti.example.com/dashboard/id/c12eb4b3-034b-49a4-b5f1-98053f950ada) |
>
>### Observable relationships
>
>|Relationship|Entity type|Entity|
>|---|---|---|
>| related-to | Malware | [Example Malware](https://opencti.example.com/dashboard/id/0e6fcea0-670c-473e-ad53-cf3f80dd7764) |

### domain

***
Checks the reputation of a domain in OpenCTI, using its observable and its indicator.

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
| OpenCTI.Indicator.score | Number | OpenCTI score (x_opencti_score) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | Date from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | Date until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date of the indicator. |
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
| OpenCTI.Observable.created | Date | Creation date of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date of the observable. |

#### Command Example

```!domain domain=suspicious.example.com```

#### Context Example

```json
{
    "Domain": {
        "Name": "suspicious.example.com"
    },
    "DBotScore": {
        "Indicator": "suspicious.example.com",
        "Type": "domain",
        "Vendor": "OpenCTI",
        "Score": 2,
        "Reliability": "B - Usually reliable"
    },
    "OpenCTI": {
        "Observable": {
            "found": false,
            "value": "suspicious.example.com",
            "type": "domain"
        },
        "Indicator": {
            "id": "95292a74-bc82-4db7-a334-e4293284af20",
            "name": "suspicious.example.com",
            "description": null,
            "patternType": "stix",
            "pattern": "[domain-name:value = 'suspicious.example.com']",
            "mainObservableType": "Domain-Name",
            "indicatorTypes": [],
            "score": 60,
            "confidence": 50,
            "validFrom": "2026-10-19T21:23:56.069Z",
            "validUntil": "2027-02-24T22:14:43.118Z",
            "revoked": false,
            "detection": false,
            "created": "2026-10-19T21:23:56.125Z",
            "updatedAt": "2026-10-19T21:23:56.125Z",
            "createdBy": null,
            "creators": [
                "admin"
            ],
            "labels": [],
            "markings": [],
            "externalReferences": [],
            "relationships": []
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for domain suspicious.example.com
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|
>|---|---|---|---|
>| suspicious.example.com | 60 | 95292a74-bc82-4db7-a334-e4293284af20 | [View in OpenCTI](https://opencti.example.com/dashboard/id/95292a74-bc82-4db7-a334-e4293284af20) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| suspicious.example.com | [domain-name:value = 'suspicious.example.com'] | 60 | 50 | 2026-10-19T21:23:56.069Z | 2027-02-24T22:14:43.118Z | false | false |

### email

***
Checks the reputation of an email address in OpenCTI, using its observable and its indicator.

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
| OpenCTI.Indicator.score | Number | OpenCTI score (x_opencti_score) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | Date from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | Date until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date of the indicator. |
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
| OpenCTI.Observable.created | Date | Creation date of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date of the observable. |

#### Command Example

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
        "Type": "email",
        "Vendor": "OpenCTI",
        "Score": 3,
        "Reliability": "B - Usually reliable"
    },
    "OpenCTI": {
        "Observable": {
            "found": true,
            "id": "d040c4fc-ba22-4de0-b2cc-b10d73000fc3",
            "value": "phishing@example.com",
            "type": "Email",
            "entityType": "Email-Addr",
            "score": 90,
            "description": null,
            "createdBy": null,
            "creators": [
                "admin"
            ],
            "labels": [],
            "markings": [],
            "externalReferences": [],
            "relationships": [],
            "created": "2026-10-19T21:23:55.638Z",
            "updatedAt": "2026-10-19T21:23:55.638Z"
        },
        "Indicator": {
            "id": "c98213ce-95ea-4604-bfe8-087a86022bf8",
            "name": "phishing@example.com",
            "description": "Simple indicator of observable {phishing@example.com}",
            "patternType": "stix",
            "pattern": "[email-addr:value = 'phishing@example.com']",
            "mainObservableType": "Email-Addr",
            "indicatorTypes": [],
            "score": 90,
            "confidence": 100,
            "validFrom": "2026-10-19T21:23:55.655Z",
            "validUntil": "2027-10-15T21:10:43.013Z",
            "revoked": false,
            "detection": false,
            "created": "2026-10-19T21:23:55.700Z",
            "updatedAt": "2026-10-19T21:23:55.700Z",
            "createdBy": null,
            "creators": [
                "admin"
            ],
            "labels": [],
            "markings": [],
            "externalReferences": [],
            "relationships": []
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for email phishing@example.com
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|Observable ID|Observable Link|
>|---|---|---|---|---|---|
>| phishing@example.com | 90 | c98213ce-95ea-4604-bfe8-087a86022bf8 | [View in OpenCTI](https://opencti.example.com/dashboard/id/c98213ce-95ea-4604-bfe8-087a86022bf8) | d040c4fc-ba22-4de0-b2cc-b10d73000fc3 | [View in OpenCTI](https://opencti.example.com/dashboard/id/d040c4fc-ba22-4de0-b2cc-b10d73000fc3) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| phishing@example.com | [email-addr:value = 'phishing@example.com'] | 90 | 100 | 2026-10-19T21:23:55.655Z | 2027-10-15T21:10:43.013Z | false | false |

### url

***
Checks the reputation of a URL in OpenCTI, using its observable and its indicator.

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
| OpenCTI.Indicator.score | Number | OpenCTI score (x_opencti_score) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | Date from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | Date until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date of the indicator. |
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
| OpenCTI.Observable.created | Date | Creation date of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date of the observable. |

#### Command Example

```!url url=https://malicious.example.com/payload```

#### Context Example

```json
{
    "URL": {
        "Data": "https://malicious.example.com/payload",
        "Malicious": {
            "Vendor": "OpenCTI",
            "Description": "OpenCTI score: 90"
        }
    },
    "DBotScore": {
        "Indicator": "https://malicious.example.com/payload",
        "Type": "url",
        "Vendor": "OpenCTI",
        "Score": 3,
        "Reliability": "B - Usually reliable"
    },
    "OpenCTI": {
        "Observable": {
            "found": true,
            "id": "6057caed-e735-45d8-9513-6f9e79bd75b6",
            "value": "https://malicious.example.com/payload",
            "type": "URL",
            "entityType": "Url",
            "score": 90,
            "description": null,
            "createdBy": null,
            "creators": [
                "admin"
            ],
            "labels": [],
            "markings": [],
            "externalReferences": [],
            "relationships": [],
            "created": "2026-10-19T21:23:55.399Z",
            "updatedAt": "2026-10-19T21:23:55.399Z"
        },
        "Indicator": {
            "id": "98a0d727-3eff-4b97-b4b5-511523218b1f",
            "name": "https://malicious.example.com/payload",
            "description": "Simple indicator of observable {https://malicious.example.com/payload}",
            "patternType": "stix",
            "pattern": "[url:value = 'https://malicious.example.com/payload']",
            "mainObservableType": "Url",
            "indicatorTypes": [],
            "score": 90,
            "confidence": 100,
            "validFrom": "2026-10-19T21:23:55.448Z",
            "validUntil": "2026-11-19T22:30:33.505Z",
            "revoked": false,
            "detection": false,
            "created": "2026-10-19T21:23:55.494Z",
            "updatedAt": "2026-10-19T21:23:55.494Z",
            "createdBy": null,
            "creators": [
                "admin"
            ],
            "labels": [],
            "markings": [],
            "externalReferences": [],
            "relationships": []
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for url https://malicious.example.com/payload
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|Observable ID|Observable Link|
>|---|---|---|---|---|---|
>| https://malicious.example.com/payload | 90 | 98a0d727-3eff-4b97-b4b5-511523218b1f | [View in OpenCTI](https://opencti.example.com/dashboard/id/98a0d727-3eff-4b97-b4b5-511523218b1f) | 6057caed-e735-45d8-9513-6f9e79bd75b6 | [View in OpenCTI](https://opencti.example.com/dashboard/id/6057caed-e735-45d8-9513-6f9e79bd75b6) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| https://malicious.example.com/payload | [url:value = 'https://malicious.example.com/payload'] | 90 | 100 | 2026-10-19T21:23:55.448Z | 2026-11-19T22:30:33.505Z | false | false |

### file

***
Checks the reputation of a file hash in OpenCTI, using its observable and its indicator.

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
| OpenCTI.Indicator.score | Number | OpenCTI score (x_opencti_score) of the indicator, used to calculate the DBot score. |
| OpenCTI.Indicator.confidence | Number | Confidence level of the indicator. |
| OpenCTI.Indicator.validFrom | Date | Date from which the indicator is valid. |
| OpenCTI.Indicator.validUntil | Date | Date until which the indicator is valid. |
| OpenCTI.Indicator.revoked | Boolean | Whether the indicator is revoked. |
| OpenCTI.Indicator.detection | Boolean | Whether the indicator is used for detection. |
| OpenCTI.Indicator.created | Date | Creation date of the indicator. |
| OpenCTI.Indicator.updatedAt | Date | Last update date of the indicator. |
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
| OpenCTI.Observable.created | Date | Creation date of the observable. |
| OpenCTI.Observable.updatedAt | Date | Last update date of the observable. |

#### Command Example

```!file file=41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84```

#### Context Example

```json
{
    "File": {
        "Hashes": [
            {
                "type": "SHA256",
                "value": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84"
            }
        ],
        "SHA256": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84",
        "Malicious": {
            "Vendor": "OpenCTI",
            "Description": "OpenCTI score: 90"
        }
    },
    "DBotScore": {
        "Indicator": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84",
        "Type": "file",
        "Vendor": "OpenCTI",
        "Score": 3,
        "Reliability": "B - Usually reliable"
    },
    "OpenCTI": {
        "Observable": {
            "found": true,
            "id": "7326b949-fdf4-4396-9eee-e31627c1d662",
            "value": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84",
            "type": "File",
            "entityType": "StixFile",
            "score": 90,
            "description": null,
            "createdBy": null,
            "creators": [
                "admin"
            ],
            "labels": [],
            "markings": [],
            "externalReferences": [],
            "relationships": [],
            "created": "2026-10-19T21:23:55.845Z",
            "updatedAt": "2026-10-19T21:23:55.845Z"
        },
        "Indicator": {
            "id": "1c397fe2-1333-4b5b-a0b1-96fb18f6e9b4",
            "name": "41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84",
            "description": "Simple indicator of observable {41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84}",
            "patternType": "stix",
            "pattern": "[file:hashes.'SHA-256' = '41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84']",
            "mainObservableType": "StixFile",
            "indicatorTypes": [],
            "score": 90,
            "confidence": 100,
            "validFrom": "2026-10-19T21:23:55.878Z",
            "validUntil": "2027-10-21T18:35:43.177Z",
            "revoked": false,
            "detection": false,
            "created": "2026-10-19T21:23:55.919Z",
            "updatedAt": "2026-10-19T21:23:55.919Z",
            "createdBy": null,
            "creators": [
                "admin"
            ],
            "labels": [],
            "markings": [],
            "externalReferences": [],
            "relationships": []
        }
    }
}
```

#### Human Readable Output

>### OpenCTI reputation for file 41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84
>
>|Value|OpenCTI Score|Indicator ID|Indicator Link|Observable ID|Observable Link|
>|---|---|---|---|---|---|
>| 41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84 | 90 | 1c397fe2-1333-4b5b-a0b1-96fb18f6e9b4 | [View in OpenCTI](https://opencti.example.com/dashboard/id/1c397fe2-1333-4b5b-a0b1-96fb18f6e9b4) | 7326b949-fdf4-4396-9eee-e31627c1d662 | [View in OpenCTI](https://opencti.example.com/dashboard/id/7326b949-fdf4-4396-9eee-e31627c1d662) |
>
>### Indicator
>
>|Name|Pattern|Score|Confidence|Valid From|Valid Until|Revoked|Detection|
>|---|---|---|---|---|---|---|---|
>| 41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84 | [file:hashes.'SHA-256' = '41d099611bfc31f99e8234be7942016551d38b3c0326630475bef6ae35995e84'] | 90 | 100 | 2026-10-19T21:23:55.878Z | 2027-10-21T18:35:43.177Z | false | false |
