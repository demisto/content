The Cortex Platform Core integration uses the Cortex API to provide commands for accessing essential services and capabilities of the Cortex Platform.

## Configure Cortex Platform Core in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| HTTP Timeout | The timeout of the HTTP requests sent to Cortex API \(in seconds\). | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### core-get-asset-details

***
Get asset information.

#### Base Command

`core-get-asset-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset unique identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.CoreAsset | unknown | Asset additional information. |
| Core.CoreAsset.xdm__asset__provider | unknown | The cloud provider or source responsible for the asset. |
| Core.CoreAsset.xdm__asset__realm | unknown | The realm or logical grouping of the asset. |
| Core.CoreAsset.xdm__asset__last_observed | unknown | The timestamp of when the asset was last observed, in ISO 8601 format. |
| Core.CoreAsset.xdm__asset__type__id | unknown | The unique identifier for the asset type. |
| Core.CoreAsset.xdm__asset__first_observed | unknown | The timestamp of when the asset was first observed, in ISO 8601 format. |
| Core.CoreAsset.asset_hierarchy | unknown | The hierarchy or structure representing the asset. |
| Core.CoreAsset.xdm__asset__type__category | unknown | The category type of the asset. |
| Core.CoreAsset.xdm__cloud__region | unknown | The cloud region where the asset resides. |
| Core.CoreAsset.xdm__asset__module_unstructured_fields | unknown | The unstructured fields or metadata associated with the asset module. |
| Core.CoreAsset.xdm__asset__source | unknown | The originating source of the asset's information. |
| Core.CoreAsset.xdm__asset__id | unknown | A unique identifier for the asset. |
| Core.CoreAsset.xdm__asset__type__class | unknown | The classification or type class of the asset. |
| Core.CoreAsset.xdm__asset__type__name | unknown | The specific name of the asset type. |
| Core.CoreAsset.xdm__asset__strong_id | unknown | The strong or immutable identifier for the asset. |
| Core.CoreAsset.xdm__asset__name | unknown | The name of the asset. |
| Core.CoreAsset.xdm__asset__raw_fields | unknown | The raw fields or unprocessed data related to the asset. |
| Core.CoreAsset.xdm__asset__normalized_fields | unknown | The normalized fields associated with the asset. |
| Core.CoreAsset.all_sources | unknown | A list of all sources providing information about the asset. |

##### Command Example

```!core-get-asset-details asset_id=123```

##### Context Example

```
{
    "Core.CoreAsset": [
        {
            "asset_hierarchy": ["123"],
            "xdm__asset__type__category": "Policy",
            "xdm__cloud__region": "Global",
            "xdm__asset__module_unstructured_fields": {},
            "xdm__asset__source": "XSIAM",
            "xdm__asset__id": "123",
            "xdm__asset__type__class": "Identity",
            "xdm__asset__normalized_fields": {},
            "xdm__asset__first_observed": 100000000,
            "xdm__asset__last_observed": 100000000,
            "xdm__asset__name": "Fake Name",
            "xdm__asset__type__name": "IAM",
            "xdm__asset__strong_id": "FAKE ID"
        }
    ]
}
```

##### Human Readable Output

>| asset_hierarchy | xdm__asset__type__category | xdm__cloud__region | xdm__asset__module_unstructured_fields | xdm__asset__source | xdm__asset__id | xdm__asset__type__class | xdm__asset__normalized_fields | xdm__asset__first_observed | xdm__asset__last_observed | xdm__asset__name |
xdm__asset__type__name | xdm__asset__strong_id |
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|123|Policy|Global||XSIAM|123|Identity||100000000|100000000|Fake Name|IAM|FAKE ID|
