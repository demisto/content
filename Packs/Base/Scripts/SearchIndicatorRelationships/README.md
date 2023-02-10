This automation outputs the indicator relationships to context according to the provided query, using the entities, entityTypes, and relationships arguments. All arguments will use the AND operator. For example, using the following arguments entities=8.8.8.8 entities_types=Domain will provide only relationships that the 8.8.8.8 indicator has with indicators of type domain.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.2.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entities | A comma-separated list of entities for which to search for relationships. For example: 192.168.1.1,192.168.1.2. The search applies to both entity A or entity B values. This argument can be used in conjunction with the entityType and the relationship arguments and all arguments will be treated with the AND operator. |
| entities_types | A comma-separated list of entity types for which to search for relationships. For example: IP,URL. This argument can be used in conjunction with the entities and the relationship arguments and all arguments will be treated with the AND operator. |
| relationships | A comma-separated list of relationship types for which to search for relationships. For example: related-to,contains. This argument can be used in conjunction with the entities and the entitiesTypes arguments and all arguments will be treated with the AND operator. |
| limit | The number of results to return. Default is 20. |
| verbose | Whether all of the relationships attributes will be returned or just the basic attributes. Default is false and the returned values will be name, entity A value, entity A type, entity B value, entity B type, relationships type. If true, all attributes will be returned. |
| revoked | The status of the relationships to return. Default is false. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Relationships.EntityA | The source of the relationship. | String |
| Relationships.EntityB | The destination of the relationship. | string |
| Relationships.Relationship | The name of the relationship. | string |
| Relationships.Reverse | The name of the reverse relationship. | string |
| Relationships.EntityAType | The type of the source of the relationship. | string |
| Relationships.EntityBType | The type of the destination of the relationship. | string |
| Relationships.ID | The ID of the relationship. | string |
| Relationships.Reliability | The reliability of the relationship. | string |
| Relationships.Brand | The brand of the relationship. | string |
| Relationships.Revoked | True if the relationship is revoked. | string |
| Relationships.FirstSeenBySource | The first time seen by the source of the relationship. | string |
| Relationships.LastSeenBySource | The last time seen by the source of the relationship. | string |
| Relationships.Description | The description of the relationship. | string |
| Relationships.Type | The type of the relationship. | string |


## Script Examples
### Example command
```!SearchIndicatorRelationships entities=google.com entities_types=IP```
### Context Example
```json
{
    "Relationships": [
        {
            "EntityA": "4.4.4.4",
            "EntityAType": "IP",
            "EntityB": "google.com",
            "EntityBType": "Domain",
            "ID": "31",
            "Relationship": "related-to",
            "Reverse": "related-to"
        },
        {
            "EntityA": "8.8.8.8",
            "EntityAType": "IP",
            "EntityB": "google.com",
            "EntityBType": "Domain",
            "ID": "30",
            "Relationship": "related-to",
            "Reverse": "related-to"
        }
    ]
}
```

### Human Readable Output

>### Relationships
>|Entity A|Entity A Type|Entity B|Entity B Type|Relationship|
>|---|---|---|---|---|
>| 4.4.4.4 | IP | google.com | Domain | related-to |
>| 8.8.8.8 | IP | google.com | Domain | related-to |

