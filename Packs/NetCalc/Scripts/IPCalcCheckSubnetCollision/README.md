An Automation Script to return subnet collision address

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
| subnet_one | First subnet |
| subnet_two | Second subnet |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IPCalc.IP.Collision.subnet1 | Collission first subnet | String |
| IPCalc.IP.Collision.subnet2 | Collission second subnet | String |
| IPCalc.IP.Collision.collision | Collission result | String |


## Script Example
```!IPCalcCheckSubnetCollision subnet_one=192.169.20.10/24 subnet_two=192.169.20.11```

## Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Collision": {
                "collision": "True",
                "subnet1": "192.169.20.10/24",
                "subnet2": "192.169.20.11"
            }
        }
    }
}
```

## Human Readable Output

>### Collision Check
>|collision|subnet1|subnet2|
>|---|---|---|
>| True | 192.169.20.10/24 | 192.169.20.11 |

