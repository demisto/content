An Automation Script to return subnet first address

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
| subnet | Subnet to use |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IPCalc.IP.Address | First ip address | String |


## Script Example
```!IPCalcReturnSubnetFirstAddress subnet=192.168.10.10/15```

## Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Allocation": {
                "allocation": "PRIVATE",
                "subnet": "192.168.10.10/15"
            }
        }
    }
}
```

## Human Readable Output

>### Iana Allocation
>|allocation|subnet|
>|---|---|
>| PRIVATE | 192.168.10.10/15 |

