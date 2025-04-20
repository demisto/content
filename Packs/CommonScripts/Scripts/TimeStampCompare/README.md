Compares a single timestamp to a list of timestamps.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 0.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* TIM - Process Domain Age With Whois

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| tested_time | Timestamp to compare to the list of timestamps. |
| values_to_compare | Values to compare the tested\_time against. The script checks each value and determines whether it's before/after/equal to the tested\_time. |
| time_format | Time format of the times you entered. By default, the script uses automatic parsing. This should be used for cases like DD/MM/YYYY. Automatic parsing will detect formats such as: February 15th 2009, 02\-15\-2020, 02\-15\-2020T14:30:00Z |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TimeStampCompare.TestedTime | The tested time | Date |
| TimeStampCompare.ComapredTime | The compared time | Date |
| TimeStampCompare.Result | Whether the tested time was before, after, or equal to the comapred time. | String |


## Script Example
```!TimeStampCompare tested_time='01-01-2020' values_to_compare='2020-02-01T00:00:00,31.12.2019'```

## Context Example
```
{
    "TimeStampCompare": [
        {
            "ComparedTime": "'2020-02-01T00:00:00",
            "Result": "after",
            "TestedTime": "'01-01-2020'"
        },
        {
            "ComparedTime": "31.12.2019'",
            "Result": "before",
            "TestedTime": "'01-01-2020'"
        }
    ]
}
```

## Human Readable Output
### Timestamp compare
|TestedTime|ComparedTime|Result|
|---|---|---|
| '01-01-2020' | '2020-02-01T00:00:00 | after |
| '01-01-2020' | 31.12.2019' | before |

