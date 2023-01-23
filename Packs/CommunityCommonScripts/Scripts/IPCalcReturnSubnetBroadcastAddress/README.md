An Automation Script to return subnet broadcast address

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
```!IPCalcReturnSubnetBroadcastAddress subnet=192.168.10.10/15```

## Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Address": "192.169.255.255"
        }
    }
}
```

## Human Readable Output

>### Broadcast Address
>|Address:|
>|---|
>| 192.169.255.255 |

