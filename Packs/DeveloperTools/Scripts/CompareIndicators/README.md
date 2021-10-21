Find the differences between two indicators lists.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| base_list | Either a list of Indicators of Compromise or an EntryID to a File containing a list. |
| compare_to_list | Either a list of Indicators of Compromise or an EntryID to a File containing a list. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IndicatorsCompare.BaseList | Indicators that appear in the first indicators list only. | String |
| IndicatorsCompare.CompareList | Indicators that appear in the second indicators list only. | String |


## Script Example
```!CompareIndicators base_list="abcd,1.1.1.0/30,2.2.2.2,3.3.3.3-3.3.3.6" compare_to_list="bcde,1.1.1.2,2.2.2.2,3.3.3.2-3.3.3.5"```

## Context Example
```json
{
    "IndicatorCompare": {
        "BaseList": [
            "1.1.1.0-1.1.1.1",
            "3.3.3.6",
            "abcd",
            "1.1.1.3"
        ],
        "CompareList": [
            "3.3.3.2",
            "bcde"
        ]
    }
}
```

## Human Readable Output

>### Results
>|BaseList|CompareList|
>|---|---|
>| 1.1.1.0-1.1.1.1,<br/>3.3.3.6,<br/>abcd,<br/>1.1.1.3 | 3.3.3.2,<br/>bcde |
