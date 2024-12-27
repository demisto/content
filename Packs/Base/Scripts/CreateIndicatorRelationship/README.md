This automation creates a relationship between indicator objects.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.2.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* ACTI Create Report-Indicator Associations

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entity_a | The source of the relationship, for example 1.1.1.1. Only a single value is acceptable. |
| entity_a_type | The source type of the relationship, for example IP. The value must be an accepted indicator type. Only a single value is acceptable. |
| entity_b | A comma-separated list of destinations or second entity values, for example 3.3.3.3,2.2.2.2. This argument must be used with the entity_b_type argument and cannot be used in conjunction with the entity_b_query argument. |
| entity_b_type | The destination type of the relationship, for example IP. Only a single value is acceptable. This argument must be used with the entity_b argument and cannot be used in conjunction with the entity_b_query argument. |
| entity_b_query | The indicator query for all the entity_b results. The indicators that are the results of the query will be used as the destination of the relationship. For example type:ip AND tags:mytag. For more query examples, see [Cortex XSOAR 6.13](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Indicators) or [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Indicator-concepts) or [Cortex XSOAR 8.7 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Indicator-concepts) This argument cannot be used in conjunction with the entity_b argument or the entity_b_type argument. |
| relationship | The name of relationship to be created. |
| reverse_relationship | The reverse name of relationship to be created. If the argument isn't provided by the user, the default reverse relation will be created. |
| source_reliability | Reliability of the source providing the intelligence data. |
| description | Free text description to add to the relationship. |
| first_seen | The time the relationship was seen. If left empty, the default value will be the time the relationship was created. Format \(YYYY-MM-DDTHH:MM:SSZ\). For example: 2020-02-02T19:00:00Z |
| create_indicator | True, if the non-existing indicators will be created according to the specified entities and their types. Default is false. |

## Outputs
---
There are no outputs for this script.

[filter (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Indicators) or [filter (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Indicator-concepts) or [Cortex XSOAR 8.7 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Indicator-concepts).