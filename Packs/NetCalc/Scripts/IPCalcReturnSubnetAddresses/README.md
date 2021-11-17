An automation script to return subnet addresses

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
| IPCalc.IP.Address | Subnet addresses | String |


## Script Example
```!IPCalcReturnSubnetAddresses subnet=192.168.20.90/28```

## Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Address": [
                "192.168.20.81",
                "192.168.20.82",
                "192.168.20.83",
                "192.168.20.84",
                "192.168.20.85",
                "192.168.20.86",
                "192.168.20.87",
                "192.168.20.88",
                "192.168.20.89",
                "192.168.20.90",
                "192.168.20.91",
                "192.168.20.92",
                "192.168.20.93",
                "192.168.20.94"
            ]
        }
    }
}
```

## Human Readable Output

>### List Addresses
>|IP Addresses:|
>|---|
>| 192.168.20.81 |
>| 192.168.20.82 |
>| 192.168.20.83 |
>| 192.168.20.84 |
>| 192.168.20.85 |
>| 192.168.20.86 |
>| 192.168.20.87 |
>| 192.168.20.88 |
>| 192.168.20.89 |
>| 192.168.20.90 |
>| 192.168.20.91 |
>| 192.168.20.92 |
>| 192.168.20.93 |
>| 192.168.20.94 |

