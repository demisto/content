Manages indicators from OpenCTI.  
This integration was tested with version 5.12.17 of OpenCTI.  

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
| all_results | When the argument is set to true, the limit argument is ignored. Default is false. Possible values are: true, false. Default is false. | Optional | 

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
```!opencti-indicator-delete id=74faf2e8-bbab-4a1a-a548-58db202c5e57```

#### Human Readable Output

>Indicator deleted.

### opencti-indicator-field-update
***
Update the indicator field. The fields that can be updated are: score, description.


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
| OpenCTI.Indicator.id | String | Updated indicator ID. | 


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
| type | The indicator type to create. Out-of-the-box indicator types supported in XSOAR are: Account, Domain, Email, File-MD5, File-SHA1, File-SHA256, Host, IP, IPV6, Registry Key, and URL. Possible values are: Account, Domain, Email, File-MD5, File-SHA1, File-SHA256, Host, IP, IPv6, Registry Key, URL. | Required | 
| created_by | Organization ID. Use opencti-organization-list to find all organization IDs in OpenCTI, or use opencti-organization-create to create a new organization ID. | Optional | 
| marking_id | Indicator marking definition ID. Use opencti-marking-definition-list to find all marking definition IDs in OpenCTI. | Optional | 
| label_id | Indicator label ID. Use opencti-label-list to find all label IDs in OpenCTI, or use opencti-label-create to create a new label. | Optional | 
| external_references_id | External references URL. Use opencti-external-reference-create to create a new external reference. | Optional | 
| description | Indicator description. | Optional | 
| score | Indicator score. Values range is 0 - 100. Default value is 50. | Optional | 
| value | Indicator value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicator.id | String | New indicator ID. |



#### Command Example
```!opencti-indicator-create type=Domain created_by=0c7cb378-64c3-4809-b423-986ac7cecf91 description=test value="TestDomainDocs.com" score=70 label_id=fa57f98e-f2f5-45fd-97f2-bf2c53119044 marking_id=9128e411-c759-4af0-aeb0-b65f12082648```

#### Context Example
```json
{
    "OpenCTI": {
        "Indicator": {
            "id": "7ed5946a-81a2-4490-8be8-06d3633a41fb",
            "type": "Domain",
            "value": "TestDomainDocs.com"
        }
    }
}
```

#### Human Readable Output

>Indicator created successfully. New Indicator id: 7ed5946a-81a2-4490-8be8-06d3633a41fb

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
| confidence | Confidence level for the indicator, value between 0 and 100. Default is 50. Default is 50. | Optional | 
| score | The score of the indicator, value between 0 and 100. Default is 50. Default is 50. | Optional | 
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
| observable_types | The observable types to fetch. Out-of-the-box observable types supported in XSOAR are: Account, Domain, Email, File, Host, IP, IPv6, Registry Key, and URL. Possible values are: ALL, Account, Domain, Email, File, Host, IP, IPv6, Registry Key, URL. Default is ALL. | Optional | 
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.ObservablesList.LastRunID context path. | Optional | 
| search | The observable's value to filter by, can be partial value. | Optional | 
| all_results | When the argument is set to true, the limit argument is ignored. Default is false. Possible values are: true, false. Default is false. | Optional | 

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
| search | The incident's value to filter by, can be partial value. | Optional | 
| created_by | The ID of the entity that created the incident (use opencti-organization-list to find or create). | Optional | 
| creator | The ID of the incident creator. | Optional | 
| created_after | Created after date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional | 
| created_before | Created before date filter. Format: YYYY-MM-DDThh:mm:ss.sssZ. | Optional | 
| incident_types | The types of the incident. Use opencti-incident-types-list to find all incident types in OpenCTI. | Optional | 
| label_id | The label ID for the incident (use opencti-label-list to find or create). | Optional | 
| limit | The maximum number of incidents to return. Default value is 50. Maximum value is 500. Default is 50. | Optional | 
| last_run_id | The last ID from the previous call, from which to begin pagination for this call. You can find this value at the OpenCTI.Incidents.LastRunID context path. | Optional | 
| all_results | When the argument is set to true, the limit argument is ignored. Default is false. Possible values are: true, false. Default is false. | Optional | 

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

