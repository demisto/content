An Automation Script to return subnet network ID

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
| IPCalc.IP.Network | Subnet network | String |


## Script Example
```!IPCalcReturnSubnetNetwork subnet=192.168.10.10/15```

## Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Network": "192.168.0.0/15"
        }
    }
}
```

## Human Readable Output

>### Subnet Network
>|Network:|
>|---|
>| 192.168.0.0/15 |

