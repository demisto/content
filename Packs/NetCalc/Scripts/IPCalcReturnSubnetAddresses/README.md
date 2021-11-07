An Automation Script to return Subnet Addresses

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
```!IPCalcReturnSubnetAddresses subnet=192.168.10.10/29```

## Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Address": [
                "192.168.10.9",
                "192.168.10.10",
                "192.168.10.11",
                "192.168.10.12",
                "192.168.10.13",
                "192.168.10.14"
            ]
        }
    }
}
```

## Human Readable Output

>### List Addresses
>|IP Addresses:|
>|---|
>| 192.168.10.9 |
>| 192.168.10.10 |
>| 192.168.10.11 |
>| 192.168.10.12 |
>| 192.168.10.13 |
>| 192.168.10.14 |

