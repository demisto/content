An automation script to return address in binary format

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
| IPCalc.IP.Binary.binary | Subnet binary | String |
| IPCalc.IP.Binary.address | IP address | String |


## Script Example
```!IPCalcReturnAddressBinary ip_address=192.158.2.2```

## Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Binary": {
                "address": "192.158.2.2",
                "binary": "11000000100111100000001000000010"
            }
        }
    }
}
```

## Human Readable Output

>### Subnet Binary
>|address|binary|
>|---|---|
>| 192.158.2.2 | 11000000100111100000001000000010 |

