Get a range of indexes from a list.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, general, basescript, entirelist |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| range | start_index - end_index or \[i_1,i_2,...,i_n\]. |
| value | List or single object |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Value | Transformed list. | Array |


## Script Examples
### Example command
```!GetRange range=0,1,3-5,7 value=[0,1,2,3,4,5,6,7,8,9]```
### Context Example
```json
{
    "Value": [
        0,
        1,
        3,
        4,
        5,
        7
    ]
}
```

### Human Readable Output

>### Results
>|Value|
>|---|
>| 0 |
>| 1 |
>| 3 |
>| 4 |
>| 5 |
>| 7 |

