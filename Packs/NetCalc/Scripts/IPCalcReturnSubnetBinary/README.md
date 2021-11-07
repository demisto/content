An Automation Script to return subnet in binary format

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
| IPCalc.IP.Binary.binary | Subnet binary | String |
| IPCalc.IP.Binary.subnet | Subnet address | String |


## Script Example
```!IPCalcReturnSubnetBinary subnet=192.168.10.10/24```

## Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Binary": {
                "binary": "11000000101010000000101000001010",
                "subnet": "192.168.10.10/24"
            }
        }
    }
}
```

## Human Readable Output

>### Subnet Binary
>|binary|subnet|
>|---|---|
>| 11000000101010000000101000001010 | 192.168.10.10/24 |

