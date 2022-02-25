An automation script to return address IANA information

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
| ip_address | Address to use |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IPCalc.IP.Allocation.allocation | IANA IP allocation type | String |
| IPCalc.IP.Allocation.address | Address | String |


## Script Example
```!IPCalcReturnAddressIANAAllocation ip_address=1.1.1.1```

## Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Allocation": {
                "address": "1.1.1.1",
                "allocation": "global"
            }
        }
    }
}
```

## Human Readable Output

>### Iana Allocation
>|address|allocation|
>|---|---|
>| 1.1.1.1 | global |

